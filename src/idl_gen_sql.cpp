/*
 * Copyright 2025 Google Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "idl_gen_sql.h"

#include <algorithm>
#include <string>
#include <vector>

#include "flatbuffers/code_generators.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/util.h"

namespace flatbuffers {

namespace sql {

namespace {

// SQL dialect options
enum class SqlDialect {
  kGeneric,     // Generic SQL (ANSI)
  kPostgres,    // PostgreSQL
  kMySQL,       // MySQL/MariaDB
  kSQLite,      // SQLite
};

// Convert FlatBuffers base type to SQL type
static std::string BaseTypeToSql(BaseType type, SqlDialect dialect) {
  switch (type) {
    case BASE_TYPE_BOOL:
      return dialect == SqlDialect::kMySQL ? "TINYINT(1)" : "BOOLEAN";
    case BASE_TYPE_CHAR:
      return "SMALLINT";  // int8 - most DBs don't have TINYINT
    case BASE_TYPE_UCHAR:
      return dialect == SqlDialect::kPostgres ? "SMALLINT" : "TINYINT UNSIGNED";
    case BASE_TYPE_SHORT:
      return "SMALLINT";
    case BASE_TYPE_USHORT:
      return dialect == SqlDialect::kPostgres ? "INTEGER" : "SMALLINT UNSIGNED";
    case BASE_TYPE_INT:
      return "INTEGER";
    case BASE_TYPE_UINT:
      return dialect == SqlDialect::kPostgres ? "BIGINT" : "INTEGER UNSIGNED";
    case BASE_TYPE_LONG:
      return "BIGINT";
    case BASE_TYPE_ULONG:
      return dialect == SqlDialect::kPostgres ? "NUMERIC(20,0)" : "BIGINT UNSIGNED";
    case BASE_TYPE_FLOAT:
      return "REAL";
    case BASE_TYPE_DOUBLE:
      return "DOUBLE PRECISION";
    case BASE_TYPE_STRING:
      return "TEXT";
    default:
      return "BLOB";  // For complex types, store as binary
  }
}

// Generate full table name with namespace prefix
template <class T>
static std::string GenFullName(const T* def, const std::string& separator = "_") {
  std::string full_name;
  const auto& name_spaces = def->defined_namespace->components;
  for (auto ns = name_spaces.cbegin(); ns != name_spaces.cend(); ++ns) {
    full_name.append(*ns + separator);
  }
  full_name.append(def->name);
  return full_name;
}

// Convert camelCase/PascalCase to snake_case for SQL naming convention
static std::string ToSnakeCase(const std::string& input) {
  std::string result;
  for (size_t i = 0; i < input.length(); ++i) {
    char c = input[i];
    if (std::isupper(c)) {
      if (i > 0) { result += '_'; }
      result += static_cast<char>(std::tolower(c));
    } else {
      result += c;
    }
  }
  return result;
}

// Escape SQL identifier (table/column name) if needed
static std::string EscapeIdentifier(const std::string& name, SqlDialect dialect) {
  // Reserved words that need escaping
  static const char* reserved[] = {
    "order", "group", "table", "index", "key", "value", "type",
    "user", "select", "from", "where", "join", "left", "right",
    "inner", "outer", "on", "and", "or", "not", "null", "true",
    "false", "create", "drop", "alter", "insert", "update", "delete",
    nullptr
  };

  std::string lower = name;
  std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

  bool needs_escape = false;
  for (const char** r = reserved; *r != nullptr; ++r) {
    if (lower == *r) {
      needs_escape = true;
      break;
    }
  }

  if (needs_escape) {
    switch (dialect) {
      case SqlDialect::kMySQL:
        return "`" + name + "`";
      case SqlDialect::kPostgres:
      case SqlDialect::kSQLite:
      case SqlDialect::kGeneric:
      default:
        return "\"" + name + "\"";
    }
  }
  return name;
}

class SqlGenerator : public BaseGenerator {
 public:
  SqlGenerator(const Parser& parser, const std::string& path,
               const std::string& file_name)
      : BaseGenerator(parser, path, file_name, "", "_", "sql"),
        dialect_(SqlDialect::kGeneric),
        use_snake_case_(true),
        generate_foreign_keys_(true),
        generate_indexes_(true) {
    // Parse SQL dialect option
    const auto& opts = parser.opts;
    if (opts.sql_dialect == "postgres" || opts.sql_dialect == "postgresql") {
      dialect_ = SqlDialect::kPostgres;
    } else if (opts.sql_dialect == "mysql" || opts.sql_dialect == "mariadb") {
      dialect_ = SqlDialect::kMySQL;
    } else if (opts.sql_dialect == "sqlite" || opts.sql_dialect == "sqlite3") {
      dialect_ = SqlDialect::kSQLite;
    } else {
      dialect_ = SqlDialect::kGeneric;
    }

    // Parse other SQL options (use defaults if not set in options)
    use_snake_case_ = opts.sql_snake_case;
    generate_foreign_keys_ = opts.sql_foreign_keys;
    generate_indexes_ = opts.sql_indexes;
  }

  bool generate() {
    code_.clear();

    // Generate header comment
    code_ += "-- SQL DDL generated from FlatBuffers schema\n";
    code_ += "-- Source: " + file_name_ + ".fbs\n";
    code_ += "-- Generated by flatc --sql\n";
    code_ += "--\n";
    code_ += "-- This file contains CREATE TABLE statements for all tables\n";
    code_ += "-- defined in the FlatBuffers schema.\n";
    code_ += "--\n\n";

    // First pass: Generate enum types (for PostgreSQL) or comments
    for (auto it = parser_.enums_.vec.begin();
         it != parser_.enums_.vec.end(); ++it) {
      auto& enum_def = **it;
      if (enum_def.is_union) continue;  // Skip unions
      GenerateEnum(enum_def);
    }

    // Second pass: Generate tables
    for (auto it = parser_.structs_.vec.begin();
         it != parser_.structs_.vec.end(); ++it) {
      auto& struct_def = **it;
      if (struct_def.fixed) continue;  // Skip fixed structs (no SQL equivalent)
      GenerateTable(struct_def);
    }

    // Third pass: Generate junction tables for relationships
    GenerateJunctionTables();

    // Fourth pass: Generate foreign key constraints (if enabled)
    if (generate_foreign_keys_) {
      GenerateForeignKeys();
    }

    // Fifth pass: Generate indexes for key fields
    if (generate_indexes_) {
      GenerateIndexes();
    }

    return true;
  }

  bool save() const {
    const auto file_path = GeneratedFileName(path_, file_name_, parser_.opts);
    return parser_.opts.file_saver->SaveFile(file_path.c_str(), code_, false);
  }

  const std::string& GetCode() const { return code_; }

 private:
  void GenerateEnum(const EnumDef& enum_def) {
    std::string name = GetTableName(GenFullName(&enum_def, "_"));

    code_ += "-- Enum: " + enum_def.name + "\n";

    if (dialect_ == SqlDialect::kPostgres) {
      // PostgreSQL supports CREATE TYPE for enums
      code_ += "CREATE TYPE " + name + " AS ENUM (\n";
      auto& vals = enum_def.Vals();
      for (auto it = vals.begin(); it != vals.end(); ++it) {
        code_ += "  '" + (*it)->name + "'";
        if (std::next(it) != vals.end()) {
          code_ += ",";
        }
        code_ += "\n";
      }
      code_ += ");\n\n";
    } else {
      // For other dialects, generate a comment with enum values
      code_ += "-- Values: ";
      auto& vals = enum_def.Vals();
      for (auto it = vals.begin(); it != vals.end(); ++it) {
        code_ += (*it)->name + "=" + NumToString((*it)->GetAsInt64());
        if (std::next(it) != vals.end()) {
          code_ += ", ";
        }
      }
      code_ += "\n";

      // Generate a lookup table for the enum
      code_ += "CREATE TABLE " + name + " (\n";
      code_ += "  id INTEGER PRIMARY KEY,\n";
      code_ += "  name TEXT NOT NULL UNIQUE\n";
      code_ += ");\n\n";

      // Generate INSERT statements for enum values
      code_ += "-- Populate enum lookup table\n";
      for (auto it = vals.begin(); it != vals.end(); ++it) {
        code_ += "INSERT INTO " + name + " (id, name) VALUES (";
        code_ += NumToString((*it)->GetAsInt64()) + ", '";
        code_ += (*it)->name + "');\n";
      }
      code_ += "\n";
    }
  }

  void GenerateTable(const StructDef& struct_def) {
    std::string table_name = GetTableName(GenFullName(&struct_def, "_"));

    code_ += "-- Table: " + struct_def.name;
    if (!struct_def.doc_comment.empty()) {
      code_ += " - " + struct_def.doc_comment[0];
    }
    code_ += "\n";
    code_ += "CREATE TABLE " + EscapeIdentifier(table_name, dialect_) + " (\n";

    // First, collect all fields that will generate columns
    // (excluding deprecated and junction-table fields)
    auto& fields = struct_def.fields.vec;
    std::vector<const FieldDef*> column_fields;
    for (auto it = fields.begin(); it != fields.end(); ++it) {
      auto& field = **it;
      if (field.deprecated) continue;
      if (SkipColumnForJunction(field)) continue;
      column_fields.push_back(&field);
    }

    // Add auto-increment primary key if no key field exists
    bool has_key = struct_def.has_key;
    if (!has_key) {
      code_ += "  id ";
      if (dialect_ == SqlDialect::kPostgres) {
        code_ += "SERIAL PRIMARY KEY";
      } else if (dialect_ == SqlDialect::kSQLite) {
        code_ += "INTEGER PRIMARY KEY AUTOINCREMENT";
      } else {
        code_ += "INTEGER PRIMARY KEY AUTO_INCREMENT";
      }
      if (!column_fields.empty()) {
        code_ += ",";
      }
      code_ += "\n";
    }

    // Generate columns for each field
    for (size_t i = 0; i < column_fields.size(); ++i) {
      auto& field = *column_fields[i];
      GenerateColumn(field, has_key);
      if (i < column_fields.size() - 1) {
        code_ += ",";
      }
      code_ += "\n";
    }
    code_ += ");\n\n";
  }

  // Returns true if this field should skip column generation (uses junction table)
  bool SkipColumnForJunction(const FieldDef& field) {
    const Type& type = field.value.type;

    // Union type discriminator field (auto-generated _type field) - handled by junction table
    if (type.base_type == BASE_TYPE_UTYPE) return true;

    // Unions use junction tables
    if (type.base_type == BASE_TYPE_UNION) return true;

    // Vectors of tables use junction tables
    if ((type.base_type == BASE_TYPE_VECTOR || type.base_type == BASE_TYPE_VECTOR64) &&
        type.element == BASE_TYPE_STRUCT && type.struct_def != nullptr &&
        !type.struct_def->fixed) {
      return true;
    }

    // Vectors of unions use junction tables
    if ((type.base_type == BASE_TYPE_VECTOR || type.base_type == BASE_TYPE_VECTOR64) &&
        type.element == BASE_TYPE_UNION) {
      return true;
    }

    return false;
  }

  void GenerateColumn(const FieldDef& field, bool parent_has_key) {
    std::string col_name = GetColumnName(field.name);
    std::string col_type;
    std::string constraints;

    const Type& type = field.value.type;

    switch (type.base_type) {
      case BASE_TYPE_STRUCT:
        // Reference to another table - use foreign key
        col_type = "INTEGER";  // FK reference
        // Foreign key will be added in separate pass
        break;

      case BASE_TYPE_UNION:
        // Unions are handled via junction tables (should be skipped before calling)
        return;

      case BASE_TYPE_VECTOR:
      case BASE_TYPE_VECTOR64:
        // Vectors of scalars/strings stored as JSON or array
        // (vectors of tables/unions are skipped before calling)
        if (dialect_ == SqlDialect::kPostgres) {
          if (IsScalar(type.element)) {
            col_type = BaseTypeToSql(type.element, dialect_) + "[]";
          } else {
            col_type = "JSONB";
          }
        } else if (dialect_ == SqlDialect::kMySQL) {
          col_type = "JSON";
        } else {
          col_type = "TEXT";  // Store as JSON text
        }
        break;

      case BASE_TYPE_ARRAY:
        // Fixed-size arrays - similar to vectors
        if (dialect_ == SqlDialect::kPostgres) {
          col_type = BaseTypeToSql(type.element, dialect_) +
                     "[" + NumToString(type.fixed_length) + "]";
        } else {
          col_type = "TEXT";  // Store as JSON
        }
        break;

      default:
        col_type = BaseTypeToSql(type.base_type, dialect_);

        // Handle enums - reference the enum lookup table
        if (type.enum_def != nullptr && !type.enum_def->is_union) {
          if (dialect_ == SqlDialect::kPostgres) {
            col_type = GetTableName(GenFullName(type.enum_def, "_"));
          }
          // For other dialects, keep as INTEGER (FK to enum table)
        }
        break;
    }

    // Add constraints
    if (field.key) {
      constraints += " PRIMARY KEY";
    }
    if (field.IsRequired()) {
      constraints += " NOT NULL";
    }
    if (field.value.constant != "0" && !field.value.constant.empty()) {
      // Has default value
      const std::string& val = field.value.constant;

      // Check for special float values (nan, inf) - SQLite doesn't support these
      bool is_special_float = false;
      if (IsFloat(type.base_type) && dialect_ == SqlDialect::kSQLite) {
        std::string lower_val = val;
        std::transform(lower_val.begin(), lower_val.end(), lower_val.begin(), ::tolower);
        // Remove leading + sign for comparison
        if (!lower_val.empty() && lower_val[0] == '+') {
          lower_val = lower_val.substr(1);
        }
        if (lower_val == "nan" || lower_val == "inf" || lower_val == "-inf" ||
            lower_val == "infinity" || lower_val == "-infinity") {
          is_special_float = true;
        }
      }

      if (!is_special_float) {
        if (IsString(type)) {
          constraints += " DEFAULT '" + val + "'";
        } else if (type.base_type == BASE_TYPE_BOOL) {
          constraints += " DEFAULT ";
          constraints += (val == "true" || val == "1") ? "TRUE" : "FALSE";
        } else {
          constraints += " DEFAULT " + val;
        }
      }
      // For SQLite: special float values (nan, inf) are omitted as SQLite
      // doesn't support these literal values
    }

    code_ += "  " + EscapeIdentifier(col_name, dialect_) + " " + col_type + constraints;

    // Add comment with field documentation
    if (!field.doc_comment.empty()) {
      if (dialect_ == SqlDialect::kPostgres || dialect_ == SqlDialect::kMySQL) {
        // These dialects support COMMENT
      }
    }
  }

  void GenerateJunctionTables() {
    code_ += "-- Junction Tables (for relationships)\n";
    code_ += "-- These tables link parent tables to child tables for references and vectors.\n";
    code_ += "--\n\n";

    for (auto it = parser_.structs_.vec.begin();
         it != parser_.structs_.vec.end(); ++it) {
      auto& struct_def = **it;
      if (struct_def.fixed) continue;

      std::string parent_table = GetTableName(GenFullName(&struct_def, "_"));

      for (auto fit = struct_def.fields.vec.begin();
           fit != struct_def.fields.vec.end(); ++fit) {
        auto& field = **fit;
        if (field.deprecated) continue;

        const Type& type = field.value.type;
        std::string field_name = GetColumnName(field.name);

        // Single table reference: Monster.weapon → Weapon
        if (type.base_type == BASE_TYPE_STRUCT && type.struct_def != nullptr &&
            !type.struct_def->fixed) {
          std::string child_table = GetTableName(GenFullName(type.struct_def, "_"));
          std::string junction_name = parent_table + "__" + field_name;

          code_ += "-- Junction: " + struct_def.name + "." + field.name;
          code_ += " → " + type.struct_def->name + " (0..1)\n";
          code_ += "CREATE TABLE " + EscapeIdentifier(junction_name, dialect_) + " (\n";
          code_ += "  id INTEGER PRIMARY KEY";
          if (dialect_ == SqlDialect::kPostgres) {
            code_ = code_.substr(0, code_.length() - 19);  // Remove "INTEGER PRIMARY KEY"
            code_ += "SERIAL PRIMARY KEY";
          }
          code_ += ",\n";
          code_ += "  parent_rowid INTEGER NOT NULL,\n";
          code_ += "  child_rowid INTEGER NOT NULL,\n";
          code_ += "  created_at INTEGER DEFAULT (strftime('%s', 'now')),\n";
          code_ += "  UNIQUE(parent_rowid)\n";  // 0..1 relationship
          code_ += ");\n\n";
        }

        // Vector of tables: Monster.weapons → [Weapon]
        if ((type.base_type == BASE_TYPE_VECTOR || type.base_type == BASE_TYPE_VECTOR64) &&
            type.element == BASE_TYPE_STRUCT && type.struct_def != nullptr &&
            !type.struct_def->fixed) {
          std::string child_table = GetTableName(GenFullName(type.struct_def, "_"));
          std::string junction_name = parent_table + "__" + field_name;

          code_ += "-- Junction: " + struct_def.name + "." + field.name;
          code_ += " → [" + type.struct_def->name + "] (0..N)\n";
          code_ += "CREATE TABLE " + EscapeIdentifier(junction_name, dialect_) + " (\n";
          code_ += "  id INTEGER PRIMARY KEY";
          if (dialect_ == SqlDialect::kPostgres) {
            code_ = code_.substr(0, code_.length() - 19);
            code_ += "SERIAL PRIMARY KEY";
          }
          code_ += ",\n";
          code_ += "  parent_rowid INTEGER NOT NULL,\n";
          code_ += "  vec_index INTEGER NOT NULL,\n";  // Preserves array order
          code_ += "  child_rowid INTEGER NOT NULL,\n";
          code_ += "  created_at INTEGER DEFAULT (strftime('%s', 'now')),\n";
          code_ += "  UNIQUE(parent_rowid, vec_index)\n";
          code_ += ");\n\n";
        }

        // Union type: Monster.equipment → Equipment (polymorphic)
        if (type.base_type == BASE_TYPE_UNION && type.enum_def != nullptr) {
          std::string junction_name = parent_table + "__" + field_name;

          code_ += "-- Junction: " + struct_def.name + "." + field.name;
          code_ += " → " + type.enum_def->name + " (union, 0..1)\n";
          code_ += "CREATE TABLE " + EscapeIdentifier(junction_name, dialect_) + " (\n";
          code_ += "  id INTEGER PRIMARY KEY";
          if (dialect_ == SqlDialect::kPostgres) {
            code_ = code_.substr(0, code_.length() - 19);
            code_ += "SERIAL PRIMARY KEY";
          }
          code_ += ",\n";
          code_ += "  parent_rowid INTEGER NOT NULL,\n";
          code_ += "  union_type TEXT NOT NULL,\n";  // Discriminator
          code_ += "  child_rowid INTEGER NOT NULL,\n";
          code_ += "  created_at INTEGER DEFAULT (strftime('%s', 'now')),\n";
          code_ += "  UNIQUE(parent_rowid)\n";
          code_ += ");\n";

          // Add comment with union types
          code_ += "-- Union types: ";
          auto& vals = type.enum_def->Vals();
          for (auto vit = vals.begin(); vit != vals.end(); ++vit) {
            if ((*vit)->union_type.base_type != BASE_TYPE_NONE) {
              code_ += (*vit)->name;
              if (std::next(vit) != vals.end()) code_ += ", ";
            }
          }
          code_ += "\n\n";
        }

        // Vector of unions: Monster.items → [Equipment]
        if ((type.base_type == BASE_TYPE_VECTOR || type.base_type == BASE_TYPE_VECTOR64) &&
            type.element == BASE_TYPE_UNION && type.enum_def != nullptr) {
          std::string junction_name = parent_table + "__" + field_name;

          code_ += "-- Junction: " + struct_def.name + "." + field.name;
          code_ += " → [" + type.enum_def->name + "] (union vector, 0..N)\n";
          code_ += "CREATE TABLE " + EscapeIdentifier(junction_name, dialect_) + " (\n";
          code_ += "  id INTEGER PRIMARY KEY";
          if (dialect_ == SqlDialect::kPostgres) {
            code_ = code_.substr(0, code_.length() - 19);
            code_ += "SERIAL PRIMARY KEY";
          }
          code_ += ",\n";
          code_ += "  parent_rowid INTEGER NOT NULL,\n";
          code_ += "  vec_index INTEGER NOT NULL,\n";
          code_ += "  union_type TEXT NOT NULL,\n";
          code_ += "  child_rowid INTEGER NOT NULL,\n";
          code_ += "  created_at INTEGER DEFAULT (strftime('%s', 'now')),\n";
          code_ += "  UNIQUE(parent_rowid, vec_index)\n";
          code_ += ");\n\n";
        }
      }
    }
  }

  void GenerateForeignKeys() {
    code_ += "-- Foreign Key Constraints\n";
    code_ += "-- (Uncomment to enable referential integrity)\n";
    code_ += "--\n";

    for (auto it = parser_.structs_.vec.begin();
         it != parser_.structs_.vec.end(); ++it) {
      auto& struct_def = **it;
      if (struct_def.fixed) continue;

      std::string table_name = GetTableName(GenFullName(&struct_def, "_"));

      for (auto fit = struct_def.fields.vec.begin();
           fit != struct_def.fields.vec.end(); ++fit) {
        auto& field = **fit;
        if (field.deprecated) continue;

        const Type& type = field.value.type;

        if (type.base_type == BASE_TYPE_STRUCT && type.struct_def != nullptr) {
          std::string col_name = GetColumnName(field.name);
          std::string ref_table = GetTableName(GenFullName(type.struct_def, "_"));

          code_ += "-- ALTER TABLE " + EscapeIdentifier(table_name, dialect_);
          code_ += " ADD CONSTRAINT fk_" + table_name + "_" + col_name;
          code_ += " FOREIGN KEY (" + EscapeIdentifier(col_name, dialect_) + ")";
          code_ += " REFERENCES " + EscapeIdentifier(ref_table, dialect_) + "(id);\n";
        }

        // Enum foreign keys
        if (type.enum_def != nullptr && !type.enum_def->is_union &&
            dialect_ != SqlDialect::kPostgres) {
          std::string col_name = GetColumnName(field.name);
          std::string ref_table = GetTableName(GenFullName(type.enum_def, "_"));

          code_ += "-- ALTER TABLE " + EscapeIdentifier(table_name, dialect_);
          code_ += " ADD CONSTRAINT fk_" + table_name + "_" + col_name;
          code_ += " FOREIGN KEY (" + EscapeIdentifier(col_name, dialect_) + ")";
          code_ += " REFERENCES " + EscapeIdentifier(ref_table, dialect_) + "(id);\n";
        }
      }
    }
    code_ += "\n";
  }

  void GenerateIndexes() {
    code_ += "-- Indexes\n";

    for (auto it = parser_.structs_.vec.begin();
         it != parser_.structs_.vec.end(); ++it) {
      auto& struct_def = **it;
      if (struct_def.fixed) continue;

      std::string table_name = GetTableName(GenFullName(&struct_def, "_"));

      for (auto fit = struct_def.fields.vec.begin();
           fit != struct_def.fields.vec.end(); ++fit) {
        auto& field = **fit;
        if (field.deprecated) continue;

        std::string col_name = GetColumnName(field.name);
        const Type& type = field.value.type;

        // Create index for key fields (non-primary)
        if (field.key && !struct_def.has_key) {
          code_ += "CREATE INDEX idx_" + table_name + "_" + col_name;
          code_ += " ON " + EscapeIdentifier(table_name, dialect_);
          code_ += " (" + EscapeIdentifier(col_name, dialect_) + ");\n";
        }

        // Create index for struct references (foreign keys) - on main table column
        if (type.base_type == BASE_TYPE_STRUCT && type.struct_def != nullptr) {
          code_ += "CREATE INDEX idx_" + table_name + "_" + col_name;
          code_ += " ON " + EscapeIdentifier(table_name, dialect_);
          code_ += " (" + EscapeIdentifier(col_name, dialect_) + ");\n";
        }

        // Create indexes for junction tables
        bool is_junction = false;
        if (type.base_type == BASE_TYPE_STRUCT && type.struct_def != nullptr &&
            !type.struct_def->fixed) {
          is_junction = true;
        }
        if ((type.base_type == BASE_TYPE_VECTOR || type.base_type == BASE_TYPE_VECTOR64) &&
            type.element == BASE_TYPE_STRUCT && type.struct_def != nullptr &&
            !type.struct_def->fixed) {
          is_junction = true;
        }
        if (type.base_type == BASE_TYPE_UNION && type.enum_def != nullptr) {
          is_junction = true;
        }
        if ((type.base_type == BASE_TYPE_VECTOR || type.base_type == BASE_TYPE_VECTOR64) &&
            type.element == BASE_TYPE_UNION) {
          is_junction = true;
        }

        if (is_junction) {
          std::string junction_name = table_name + "__" + col_name;
          code_ += "CREATE INDEX idx_" + junction_name + "_parent";
          code_ += " ON " + EscapeIdentifier(junction_name, dialect_);
          code_ += " (parent_rowid);\n";
          code_ += "CREATE INDEX idx_" + junction_name + "_child";
          code_ += " ON " + EscapeIdentifier(junction_name, dialect_);
          code_ += " (child_rowid);\n";
        }
      }
    }
    code_ += "\n";
  }

  std::string GetTableName(const std::string& name) {
    return use_snake_case_ ? ToSnakeCase(name) : name;
  }

  std::string GetColumnName(const std::string& name) {
    return use_snake_case_ ? ToSnakeCase(name) : name;
  }

  std::string code_;
  SqlDialect dialect_;
  bool use_snake_case_;
  bool generate_foreign_keys_;
  bool generate_indexes_;
};

}  // namespace

static bool GenerateSql(const Parser& parser, const std::string& path,
                        const std::string& file_name) {
  sql::SqlGenerator generator(parser, path, file_name);
  if (!generator.generate()) {
    return false;
  }
  return generator.save();
}

class SqlCodeGenerator : public CodeGenerator {
 public:
  Status GenerateCode(const Parser& parser, const std::string& path,
                      const std::string& filename) override {
    if (!GenerateSql(parser, path, filename)) {
      return Status::ERROR;
    }
    return Status::OK;
  }

  Status GenerateCode(const uint8_t*, int64_t, const CodeGenOptions&) override {
    return Status::NOT_IMPLEMENTED;
  }

  Status GenerateMakeRule(const Parser& parser, const std::string& path,
                          const std::string& filename,
                          std::string& output) override {
    (void)parser;
    (void)path;
    (void)filename;
    (void)output;
    return Status::NOT_IMPLEMENTED;
  }

  Status GenerateGrpcCode(const Parser& parser, const std::string& path,
                          const std::string& filename) override {
    (void)parser;
    (void)path;
    (void)filename;
    return Status::NOT_IMPLEMENTED;
  }

  Status GenerateRootFile(const Parser& parser,
                          const std::string& path) override {
    (void)parser;
    (void)path;
    return Status::NOT_IMPLEMENTED;
  }

  bool IsSchemaOnly() const override { return true; }

  bool SupportsBfbsGeneration() const override { return false; }

  bool SupportsRootFileGeneration() const override { return false; }

  IDLOptions::Language Language() const override {
    return IDLOptions::kSql;
  }

  std::string LanguageName() const override { return "SQL"; }
};

}  // namespace sql

std::unique_ptr<CodeGenerator> NewSqlCodeGenerator() {
  return std::unique_ptr<sql::SqlCodeGenerator>(new sql::SqlCodeGenerator());
}

}  // namespace flatbuffers
