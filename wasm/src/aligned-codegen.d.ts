/**
 * Type definitions for aligned-codegen module
 */

export interface ScalarTypeInfo {
  size: number;
  align: number;
  cppType: string;
  tsGetter: string;
  tsSetter: string;
  tsType: string;
}

export interface EnumValue {
  name: string;
  value: number | null;
}

export interface EnumDef {
  name: string;
  baseType: string;
  values: EnumValue[];
}

export interface FieldDef {
  name: string;
  type: string;
  isArray: boolean;
  arraySize: number;
  size: number;
  align: number;
  cppType?: string;
  tsGetter?: string;
  tsSetter?: string;
  tsType?: string;
  isEnum?: boolean;
  enumDef?: EnumDef;
  isNestedStruct?: boolean;
}

export interface StructDef {
  name: string;
  fields: FieldDef[];
  isStruct: boolean;
}

export interface ParsedSchema {
  namespace: string | null;
  structs: StructDef[];
  tables: StructDef[];
  enums: EnumDef[];
}

export interface LayoutField extends FieldDef {
  offset: number;
  padding: number;
  nestedLayout?: StructLayout;
}

export interface StructLayout {
  name: string;
  fields: LayoutField[];
  size: number;
  align: number;
  finalPadding: number;
}

export interface GenerationOptions {
  /** Include traditional #ifndef guard (default: true) */
  includeGuard?: boolean;
  /** Use #pragma once (default: true) */
  pragmaOnce?: boolean;
  /** Module type for TypeScript: 'esm' | 'cjs' (default: 'esm') */
  moduleType?: 'esm' | 'cjs';
}

export interface GeneratedCode {
  /** C++ header content */
  cpp: string;
  /** TypeScript module content */
  ts: string;
  /** Parsed schema */
  schema: ParsedSchema;
  /** Computed layouts for each struct */
  layouts: Record<string, StructLayout>;
}

/**
 * Parse a FlatBuffers schema and extract struct/table definitions
 * @param schemaContent - The .fbs schema content
 * @returns Parsed schema with structs, tables, and enums
 */
export function parseSchema(schemaContent: string): ParsedSchema;

/**
 * Compute aligned layout for a struct
 * @param structDef - Struct definition with fields
 * @param allStructs - Map of all structs for nested resolution
 * @returns Layout with computed offsets, size, and alignment
 */
export function computeLayout(
  structDef: StructDef,
  allStructs?: Record<string, StructDef>
): StructLayout;

/**
 * Generate C++ header for aligned structs
 * @param schema - Parsed schema
 * @param options - Generation options
 * @returns C++ header content
 */
export function generateCppHeader(
  schema: ParsedSchema,
  options?: GenerationOptions
): string;

/**
 * Generate TypeScript view classes for aligned structs
 * @param schema - Parsed schema
 * @param options - Generation options
 * @returns TypeScript content
 */
export function generateTypeScript(
  schema: ParsedSchema,
  options?: GenerationOptions
): string;

/**
 * Generate aligned code from a FlatBuffers schema
 * @param schemaContent - The .fbs schema content
 * @param options - Generation options
 * @returns Generated code and layout info
 */
export function generateAlignedCode(
  schemaContent: string,
  options?: GenerationOptions
): GeneratedCode;

declare const _default: {
  parseSchema: typeof parseSchema;
  computeLayout: typeof computeLayout;
  generateCppHeader: typeof generateCppHeader;
  generateTypeScript: typeof generateTypeScript;
  generateAlignedCode: typeof generateAlignedCode;
};

export default _default;
