/**
 * FlatBuffer Studio
 * Browser-based IDE for FlatBuffers with schema editing, code generation, and encryption
 */

import { EditorView, basicSetup } from 'codemirror';
import { EditorState } from '@codemirror/state';
import { json } from '@codemirror/lang-json';
import { oneDark } from '@codemirror/theme-one-dark';
import { x25519 } from '@noble/curves/ed25519';
import { Buffer } from 'buffer';

// Make Buffer available globally
window.Buffer = Buffer;

// Import FlatBuffers WASM modules
import { FlatcRunner } from '../../src/runner.mjs';
import {
  loadEncryptionWasm,
  sha256,
  hkdf,
  encryptBytes,
  decryptBytes,
} from '../../src/encryption.mjs';

// =============================================================================
// Constants
// =============================================================================

const FLATC_WASM_PATH = '../../dist/flatc.wasm';
const ENCRYPTION_WASM_PATH = '../../dist/flatc-encryption.wasm';

const SAMPLE_SCHEMA = `// Sample FlatBuffers Schema
namespace MyGame.Sample;

enum Color : byte { Red = 0, Green, Blue = 2 }

struct Vec3 {
  x: float;
  y: float;
  z: float;
}

table Monster {
  pos: Vec3;
  mana: short = 150;
  hp: short = 100;
  name: string;
  friendly: bool = false;
  inventory: [ubyte];
  color: Color = Blue;
  weapons: [Weapon];
  equipped: Equipment;
  path: [Vec3];
}

table Weapon {
  name: string;
  damage: short;
}

union Equipment { Weapon }

root_type Monster;
file_identifier "MONS";
`;

const SAMPLE_JSON_SCHEMA = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Person",
  "type": "object",
  "properties": {
    "firstName": {
      "type": "string",
      "description": "The person's first name"
    },
    "lastName": {
      "type": "string",
      "description": "The person's last name"
    },
    "age": {
      "type": "integer",
      "description": "Age in years",
      "minimum": 0
    },
    "email": {
      "type": "string",
      "format": "email"
    }
  },
  "required": ["firstName", "lastName"]
}`;

// =============================================================================
// State
// =============================================================================

const state = {
  initialized: false,
  flatcRunner: null,
  encryptionReady: false,

  // Editors
  schemaEditor: null,
  codeEditor: null,

  // Schema state
  schemaType: 'fbs',
  parsedSchema: null,
  tables: [],
  enums: [],
  structs: [],

  // Builder state
  currentBuffer: null,
  encryptionKey: null,

  // Bulk generator state
  bulkRecords: [],
};

// =============================================================================
// DOM Helpers
// =============================================================================

const $ = (id) => document.getElementById(id);
const $$ = (sel) => document.querySelectorAll(sel);

// =============================================================================
// Initialization
// =============================================================================

async function init() {
  try {
    updateStatus('Loading WASM modules...', 'loading');

    // Initialize WASM modules in parallel
    const [flatcRunner] = await Promise.all([
      FlatcRunner.create(FLATC_WASM_PATH),
      loadEncryptionWasm(ENCRYPTION_WASM_PATH).then(() => {
        state.encryptionReady = true;
      }).catch(err => {
        console.warn('Encryption module failed to load:', err);
      }),
    ]);

    state.flatcRunner = flatcRunner;
    state.initialized = true;

    updateStatus('Ready', 'ready');

    // Initialize editors
    initSchemaEditor();
    initCodeEditor();

    // Set up event listeners
    setupEventListeners();

    // Load sample schema
    loadSampleSchema();

  } catch (err) {
    console.error('Initialization failed:', err);
    updateStatus('Failed to load', 'error');
  }
}

function updateStatus(text, status) {
  const indicator = $('status-indicator');
  const statusText = indicator.querySelector('.status-text');

  indicator.className = 'status-indicator';
  if (status) indicator.classList.add(status);
  statusText.textContent = text;
}

// =============================================================================
// Editors
// =============================================================================

function initSchemaEditor() {
  const extensions = [
    basicSetup,
    oneDark,
    EditorView.lineWrapping,
    EditorState.tabSize.of(2),
  ];

  state.schemaEditor = new EditorView({
    parent: $('schema-editor'),
    state: EditorState.create({
      doc: '',
      extensions,
    }),
  });
}

function initCodeEditor() {
  const extensions = [
    basicSetup,
    oneDark,
    EditorView.lineWrapping,
    EditorView.editable.of(false),
    EditorState.tabSize.of(2),
  ];

  state.codeEditor = new EditorView({
    parent: $('generated-code'),
    state: EditorState.create({
      doc: '// Generated code will appear here',
      extensions,
    }),
  });
}

function setEditorContent(editor, content) {
  editor.dispatch({
    changes: {
      from: 0,
      to: editor.state.doc.length,
      insert: content,
    },
  });
}

function getEditorContent(editor) {
  return editor.state.doc.toString();
}

// =============================================================================
// Event Listeners
// =============================================================================

function setupEventListeners() {
  // Tab navigation
  $$('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      const tabId = tab.dataset.tab;
      switchTab(tabId);
    });
  });

  // Schema type selector
  $('schema-type').addEventListener('change', (e) => {
    state.schemaType = e.target.value;
  });

  // Load sample button
  $('load-sample').addEventListener('click', loadSampleSchema);

  // Upload schema
  $('upload-schema').addEventListener('change', handleSchemaUpload);

  // Parse schema button
  $('parse-schema').addEventListener('click', parseSchema);

  // Code generation
  $('generate-code').addEventListener('click', generateCode);
  $('copy-code').addEventListener('click', copyGeneratedCode);
  $('download-code').addEventListener('click', downloadGeneratedCode);

  // Builder
  $('builder-table').addEventListener('change', (e) => {
    if (e.target.value) {
      buildFormForTable(e.target.value);
    }
  });
  $('build-buffer').addEventListener('click', buildBuffer);
  $('clear-form').addEventListener('click', clearBuilderForm);
  $('download-buffer').addEventListener('click', downloadBuffer);
  $('upload-buffer').addEventListener('change', handleBufferUpload);

  // Bulk generator
  $('generate-bulk').addEventListener('click', generateBulkRecords);
  $('download-bulk').addEventListener('click', downloadBulkRecords);

  // Downloads
  $('download-flatc-wasm')?.addEventListener('click', () => downloadFile(FLATC_WASM_PATH, 'flatc.wasm'));
  $('download-flatc-js')?.addEventListener('click', () => downloadFile('../../src/runner.mjs', 'flatc-runner.mjs'));
  $('download-enc-wasm')?.addEventListener('click', () => downloadFile(ENCRYPTION_WASM_PATH, 'flatc-encryption.wasm'));
  $('download-enc-js')?.addEventListener('click', () => downloadFile('../../src/encryption.mjs', 'encryption.mjs'));

  // Modal
  $$('.modal-close, .modal-cancel, .modal-backdrop').forEach(el => {
    el.addEventListener('click', closeModal);
  });

  $('generate-key')?.addEventListener('click', generateEncryptionKey);
  $('save-encryption')?.addEventListener('click', saveEncryptionKey);

  // Encryption checkbox
  $('encrypt-buffer')?.addEventListener('change', (e) => {
    if (e.target.checked && !state.encryptionKey) {
      openEncryptionModal();
    }
  });
}

function switchTab(tabId) {
  // Update tab buttons
  $$('.nav-tab').forEach(tab => {
    tab.classList.toggle('active', tab.dataset.tab === tabId);
  });

  // Update tab content
  $$('.tab-content').forEach(content => {
    content.classList.toggle('active', content.id === `tab-${tabId}`);
  });
}

// =============================================================================
// Schema Handling
// =============================================================================

function loadSampleSchema() {
  const sample = state.schemaType === 'json' ? SAMPLE_JSON_SCHEMA : SAMPLE_SCHEMA;
  setEditorContent(state.schemaEditor, sample);
  setSchemaStatus('Sample schema loaded', 'success');
}

function handleSchemaUpload(e) {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (event) => {
    setEditorContent(state.schemaEditor, event.target.result);
    setSchemaStatus(`Loaded ${file.name}`, 'success');
  };
  reader.readAsText(file);
}

async function parseSchema() {
  if (!state.flatcRunner) {
    setSchemaStatus('WASM not loaded', 'error');
    return;
  }

  const schemaContent = getEditorContent(state.schemaEditor);
  if (!schemaContent.trim()) {
    setSchemaStatus('Schema is empty', 'error');
    return;
  }

  try {
    setSchemaStatus('Parsing...', '');

    // For FBS schemas, use flatc to parse
    if (state.schemaType === 'fbs') {
      const result = await state.flatcRunner.run({
        args: ['--binary', '--schema', '-o', '/output/', '/schema.fbs'],
        files: {
          '/schema.fbs': schemaContent,
        },
      });

      if (result.exitCode !== 0) {
        throw new Error(result.stderr || 'Schema parsing failed');
      }

      // Parse the schema manually for UI
      state.parsedSchema = parseFBSSchema(schemaContent);
    } else {
      // JSON Schema
      state.parsedSchema = JSON.parse(schemaContent);
    }

    // Update UI
    updateParsedView();
    updateTableSelectors();
    setSchemaStatus('Schema parsed successfully', 'success');

  } catch (err) {
    console.error('Parse error:', err);
    setSchemaStatus(err.message, 'error');
  }
}

function parseFBSSchema(content) {
  const schema = {
    namespace: '',
    tables: [],
    structs: [],
    enums: [],
    unions: [],
    rootType: '',
    fileIdentifier: '',
  };

  // Parse namespace
  const nsMatch = content.match(/namespace\s+([\w.]+)\s*;/);
  if (nsMatch) schema.namespace = nsMatch[1];

  // Parse root_type
  const rootMatch = content.match(/root_type\s+(\w+)\s*;/);
  if (rootMatch) schema.rootType = rootMatch[1];

  // Parse file_identifier
  const fidMatch = content.match(/file_identifier\s+"(\w+)"\s*;/);
  if (fidMatch) schema.fileIdentifier = fidMatch[1];

  // Parse enums
  const enumRegex = /enum\s+(\w+)\s*:\s*(\w+)\s*\{([^}]+)\}/g;
  let match;
  while ((match = enumRegex.exec(content)) !== null) {
    const values = match[3].split(',').map(v => {
      const parts = v.trim().split('=');
      return {
        name: parts[0].trim(),
        value: parts[1] ? parseInt(parts[1].trim()) : null,
      };
    }).filter(v => v.name);

    schema.enums.push({
      name: match[1],
      type: match[2],
      values,
    });
  }

  // Parse structs
  const structRegex = /struct\s+(\w+)\s*\{([^}]+)\}/g;
  while ((match = structRegex.exec(content)) !== null) {
    const fields = parseFields(match[2]);
    schema.structs.push({
      name: match[1],
      fields,
    });
  }

  // Parse tables
  const tableRegex = /table\s+(\w+)\s*\{([^}]+)\}/g;
  while ((match = tableRegex.exec(content)) !== null) {
    const fields = parseFields(match[2]);
    schema.tables.push({
      name: match[1],
      fields,
    });
  }

  // Parse unions
  const unionRegex = /union\s+(\w+)\s*\{([^}]+)\}/g;
  while ((match = unionRegex.exec(content)) !== null) {
    const types = match[2].split(',').map(t => t.trim()).filter(t => t);
    schema.unions.push({
      name: match[1],
      types,
    });
  }

  state.tables = schema.tables;
  state.enums = schema.enums;
  state.structs = schema.structs;

  return schema;
}

function parseFields(fieldsStr) {
  const fields = [];
  const lines = fieldsStr.split(';').filter(l => l.trim());

  for (const line of lines) {
    const match = line.trim().match(/(\w+)\s*:\s*([^=]+)(?:=\s*(.+))?/);
    if (match) {
      fields.push({
        name: match[1],
        type: match[2].trim(),
        default: match[3]?.trim(),
      });
    }
  }

  return fields;
}

function updateParsedView() {
  const container = $('parsed-view');

  if (!state.parsedSchema) {
    container.innerHTML = '<div class="empty-state"><p>Parse a schema to see its structure</p></div>';
    return;
  }

  const schema = state.parsedSchema;
  let html = '<div class="parsed-tree-content">';

  if (schema.namespace) {
    html += `<div class="tree-node-header"><span class="tree-name">namespace: ${schema.namespace}</span></div>`;
  }

  // Enums
  if (schema.enums?.length) {
    html += '<div class="tree-section"><strong>Enums</strong></div>';
    for (const e of schema.enums) {
      html += `<div class="tree-node">
        <div class="tree-node-header">
          <span class="tree-icon enum">E</span>
          <span class="tree-name">${e.name}</span>
          <span class="tree-type">: ${e.type}</span>
        </div>
        <div class="tree-children">`;
      for (const v of e.values) {
        html += `<div class="tree-node-header"><span class="tree-icon field">=</span><span class="tree-name">${v.name}</span>${v.value !== null ? `<span class="tree-type">= ${v.value}</span>` : ''}</div>`;
      }
      html += '</div></div>';
    }
  }

  // Structs
  if (schema.structs?.length) {
    html += '<div class="tree-section"><strong>Structs</strong></div>';
    for (const s of schema.structs) {
      html += `<div class="tree-node">
        <div class="tree-node-header">
          <span class="tree-icon struct">S</span>
          <span class="tree-name">${s.name}</span>
        </div>
        <div class="tree-children">`;
      for (const f of s.fields) {
        html += `<div class="tree-node-header"><span class="tree-icon field">-</span><span class="tree-name">${f.name}</span><span class="tree-type">: ${f.type}</span></div>`;
      }
      html += '</div></div>';
    }
  }

  // Tables
  if (schema.tables?.length) {
    html += '<div class="tree-section"><strong>Tables</strong></div>';
    for (const t of schema.tables) {
      html += `<div class="tree-node">
        <div class="tree-node-header">
          <span class="tree-icon table">T</span>
          <span class="tree-name">${t.name}</span>
          ${schema.rootType === t.name ? '<span class="tree-type">(root)</span>' : ''}
        </div>
        <div class="tree-children">`;
      for (const f of t.fields) {
        html += `<div class="tree-node-header"><span class="tree-icon field">-</span><span class="tree-name">${f.name}</span><span class="tree-type">: ${f.type}</span>${f.default ? `<span class="tree-type">= ${f.default}</span>` : ''}</div>`;
      }
      html += '</div></div>';
    }
  }

  html += '</div>';
  container.innerHTML = html;
}

function updateTableSelectors() {
  const tables = state.tables || [];
  const options = tables.map(t => `<option value="${t.name}">${t.name}</option>`).join('');

  $('codegen-root').innerHTML = '<option value="">Auto-detect</option>' + options;
  $('builder-table').innerHTML = '<option value="">Select Table</option>' + options;
  $('bulk-table').innerHTML = '<option value="">Select Table</option>' + options;
}

function setSchemaStatus(message, type) {
  const status = $('schema-status');
  status.textContent = message;
  status.className = 'status-message';
  if (type) status.classList.add(type);
}

// =============================================================================
// Code Generation
// =============================================================================

async function generateCode() {
  if (!state.flatcRunner) {
    alert('WASM not loaded');
    return;
  }

  const schemaContent = getEditorContent(state.schemaEditor);
  if (!schemaContent.trim()) {
    alert('Schema is empty');
    return;
  }

  const lang = $('codegen-lang').value;
  const genMutable = $('opt-gen-mutable').checked;
  const genObjectApi = $('opt-gen-object-api').checked;
  const reflectNames = $('opt-reflect-names').checked;

  // Build flatc arguments
  const args = ['-o', '/output/'];

  switch (lang) {
    case 'ts':
      args.push('--ts');
      if (genMutable) args.push('--gen-mutable');
      if (genObjectApi) args.push('--gen-object-api');
      if (reflectNames) args.push('--reflect-names');
      break;
    case 'js':
      args.push('--js');
      if (genMutable) args.push('--gen-mutable');
      if (genObjectApi) args.push('--gen-object-api');
      break;
    case 'json-schema':
      args.push('--jsonschema');
      break;
  }

  args.push('/schema.fbs');

  try {
    const result = await state.flatcRunner.run({
      args,
      files: {
        '/schema.fbs': schemaContent,
      },
    });

    if (result.exitCode !== 0) {
      throw new Error(result.stderr || 'Code generation failed');
    }

    // Get generated files
    const outputs = result.files || {};
    const outputFiles = Object.keys(outputs).filter(f => f.startsWith('/output/'));

    if (outputFiles.length === 0) {
      throw new Error('No output files generated');
    }

    // Combine all output files
    let code = '';
    for (const file of outputFiles) {
      code += `// ============= ${file.replace('/output/', '')} =============\n\n`;
      code += outputs[file];
      code += '\n\n';
    }

    setEditorContent(state.codeEditor, code);

  } catch (err) {
    console.error('Code generation error:', err);
    setEditorContent(state.codeEditor, `// Error: ${err.message}`);
  }
}

function copyGeneratedCode() {
  const code = getEditorContent(state.codeEditor);
  navigator.clipboard.writeText(code);
}

function downloadGeneratedCode() {
  const code = getEditorContent(state.codeEditor);
  const lang = $('codegen-lang').value;
  const ext = lang === 'ts' ? 'ts' : lang === 'js' ? 'js' : 'json';
  downloadText(code, `generated.${ext}`);
}

// =============================================================================
// Data Builder
// =============================================================================

function buildFormForTable(tableName) {
  const table = state.tables.find(t => t.name === tableName);
  if (!table) return;

  const container = $('builder-form');
  let html = '';

  for (const field of table.fields) {
    html += `<div class="builder-field">
      <div class="builder-field-label">
        <span class="builder-field-name">${field.name}</span>
        <span class="builder-field-type">${field.type}</span>
      </div>
      ${getFieldInput(field)}
    </div>`;
  }

  container.innerHTML = html;
}

function getFieldInput(field) {
  const type = field.type.toLowerCase();
  const id = `field-${field.name}`;

  // Check if it's an array type
  if (type.startsWith('[') && type.endsWith(']')) {
    const innerType = type.slice(1, -1);
    return `<textarea id="${id}" class="text-input" placeholder="Enter values, one per line" rows="3"></textarea>
            <small class="builder-field-type">Array of ${innerType}</small>`;
  }

  // Check for enum
  const enumType = state.enums.find(e => e.name === field.type);
  if (enumType) {
    const options = enumType.values.map(v =>
      `<option value="${v.name}" ${field.default === v.name ? 'selected' : ''}>${v.name}</option>`
    ).join('');
    return `<select id="${id}" class="select-input">${options}</select>`;
  }

  // Check for struct
  const structType = state.structs.find(s => s.name === field.type);
  if (structType) {
    let inputs = '';
    for (const sf of structType.fields) {
      inputs += `<div style="display: flex; gap: 8px; margin-bottom: 4px;">
        <label style="min-width: 40px;">${sf.name}:</label>
        <input type="number" step="any" id="${id}-${sf.name}" class="text-input" style="flex: 1;">
      </div>`;
    }
    return inputs;
  }

  // Primitive types
  switch (type) {
    case 'bool':
      return `<select id="${id}" class="select-input">
        <option value="false" ${field.default === 'false' ? 'selected' : ''}>false</option>
        <option value="true" ${field.default === 'true' ? 'selected' : ''}>true</option>
      </select>`;

    case 'string':
      return `<input type="text" id="${id}" class="text-input" value="${field.default || ''}">`;

    case 'byte':
    case 'ubyte':
    case 'short':
    case 'ushort':
    case 'int':
    case 'uint':
    case 'long':
    case 'ulong':
      return `<input type="number" id="${id}" class="text-input" value="${field.default || ''}">`;

    case 'float':
    case 'double':
      return `<input type="number" step="any" id="${id}" class="text-input" value="${field.default || ''}">`;

    default:
      return `<input type="text" id="${id}" class="text-input" placeholder="${field.type}">`;
  }
}

function buildBuffer() {
  const tableName = $('builder-table').value;
  if (!tableName) {
    alert('Please select a table');
    return;
  }

  const table = state.tables.find(t => t.name === tableName);
  if (!table) return;

  // Collect form data
  const data = {};
  for (const field of table.fields) {
    const input = $(`field-${field.name}`);
    if (input) {
      data[field.name] = input.value;
    }
  }

  // For now, show the JSON representation
  // In a full implementation, we'd use the generated code to build the actual buffer
  const json = JSON.stringify(data, null, 2);

  // Create a simple buffer representation (placeholder)
  const encoder = new TextEncoder();
  let buffer = encoder.encode(json);

  // Encrypt if requested
  const shouldEncrypt = $('encrypt-buffer').checked;
  if (shouldEncrypt && state.encryptionKey && state.encryptionReady) {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encrypted = new Uint8Array(buffer);
    encryptBytes(state.encryptionKey, iv, encrypted);

    // Prepend IV to encrypted data
    const combined = new Uint8Array(iv.length + encrypted.length);
    combined.set(iv);
    combined.set(encrypted, iv.length);
    buffer = combined;
  }

  state.currentBuffer = buffer;

  // Display hex view
  displayHexView(buffer);

  // Update stats
  $('buffer-stats').style.display = 'flex';
  $('buffer-size').textContent = buffer.length;
  $('buffer-encrypted').textContent = shouldEncrypt ? 'Yes' : 'No';

  // Enable download
  $('download-buffer').disabled = false;

  // Show decoded view
  $('decoded-view').innerHTML = `<pre class="json-view">${syntaxHighlightJSON(json)}</pre>`;
}

function displayHexView(buffer) {
  const container = $('buffer-hex');
  let html = '';

  for (let i = 0; i < buffer.length; i += 16) {
    const offset = i.toString(16).padStart(8, '0');
    const bytes = [];
    const ascii = [];

    for (let j = 0; j < 16; j++) {
      if (i + j < buffer.length) {
        bytes.push(buffer[i + j].toString(16).padStart(2, '0'));
        const char = buffer[i + j];
        ascii.push(char >= 32 && char < 127 ? String.fromCharCode(char) : '.');
      } else {
        bytes.push('  ');
        ascii.push(' ');
      }
    }

    html += `<div class="hex-line">
      <span class="hex-offset">${offset}</span>
      <span class="hex-bytes">${bytes.join(' ')}</span>
      <span class="hex-ascii">${ascii.join('')}</span>
    </div>`;
  }

  container.innerHTML = html;
}

function syntaxHighlightJSON(json) {
  return json
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?)/g, (match) => {
      if (/:$/.test(match)) {
        return `<span class="json-key">${match}</span>`;
      }
      return `<span class="json-string">${match}</span>`;
    })
    .replace(/\b(true|false)\b/g, '<span class="json-boolean">$1</span>')
    .replace(/\b(null)\b/g, '<span class="json-null">$1</span>')
    .replace(/\b(-?\d+\.?\d*)\b/g, '<span class="json-number">$1</span>');
}

function clearBuilderForm() {
  const container = $('builder-form');
  const inputs = container.querySelectorAll('input, select, textarea');
  inputs.forEach(input => {
    if (input.type === 'checkbox') {
      input.checked = false;
    } else {
      input.value = '';
    }
  });

  state.currentBuffer = null;
  $('buffer-hex').innerHTML = '<div class="empty-state small"><p>Build a buffer to see output</p></div>';
  $('decoded-view').innerHTML = '<div class="empty-state small"><p>Build or upload a buffer to decode</p></div>';
  $('buffer-stats').style.display = 'none';
  $('download-buffer').disabled = true;
}

function downloadBuffer() {
  if (!state.currentBuffer) return;
  downloadBlob(new Blob([state.currentBuffer]), 'flatbuffer.bin');
}

function handleBufferUpload(e) {
  const file = e.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onload = (event) => {
    const buffer = new Uint8Array(event.target.result);
    state.currentBuffer = buffer;
    displayHexView(buffer);

    $('buffer-stats').style.display = 'flex';
    $('buffer-size').textContent = buffer.length;
    $('buffer-encrypted').textContent = 'Unknown';
    $('download-buffer').disabled = false;
  };
  reader.readAsArrayBuffer(file);
}

// =============================================================================
// Bulk Generator
// =============================================================================

function generateBulkRecords() {
  const tableName = $('bulk-table').value;
  if (!tableName) {
    alert('Please select a table');
    return;
  }

  const table = state.tables.find(t => t.name === tableName);
  if (!table) return;

  const count = parseInt($('bulk-count').value) || 100;
  const shouldEncrypt = $('bulk-encrypt').checked;
  const seed = $('bulk-seed').value || null;

  // Initialize random with seed if provided
  const rng = seed ? seededRandom(seed) : Math.random;

  state.bulkRecords = [];

  for (let i = 0; i < count; i++) {
    const record = {};

    for (const field of table.fields) {
      record[field.name] = generateRandomValue(field, rng);
    }

    state.bulkRecords.push(record);
  }

  // Update UI
  displayBulkRecords();
  $('bulk-stats').textContent = `${count} records generated`;
  $('download-bulk').disabled = false;
}

function generateRandomValue(field, rng) {
  const type = field.type.toLowerCase();

  // Array types
  if (type.startsWith('[') && type.endsWith(']')) {
    const innerType = type.slice(1, -1);
    const length = Math.floor(rng() * 5) + 1;
    return Array.from({ length }, () =>
      generateRandomValue({ ...field, type: innerType }, rng)
    );
  }

  // Enum types
  const enumType = state.enums.find(e => e.name === field.type);
  if (enumType) {
    const idx = Math.floor(rng() * enumType.values.length);
    return enumType.values[idx].name;
  }

  // Struct types
  const structType = state.structs.find(s => s.name === field.type);
  if (structType) {
    const obj = {};
    for (const sf of structType.fields) {
      obj[sf.name] = generateRandomValue(sf, rng);
    }
    return obj;
  }

  // Primitive types
  switch (type) {
    case 'bool':
      return rng() > 0.5;
    case 'string':
      return generateRandomString(rng);
    case 'byte':
      return Math.floor(rng() * 256) - 128;
    case 'ubyte':
      return Math.floor(rng() * 256);
    case 'short':
      return Math.floor(rng() * 65536) - 32768;
    case 'ushort':
      return Math.floor(rng() * 65536);
    case 'int':
      return Math.floor(rng() * 4294967296) - 2147483648;
    case 'uint':
      return Math.floor(rng() * 4294967296);
    case 'long':
    case 'ulong':
      return BigInt(Math.floor(rng() * Number.MAX_SAFE_INTEGER));
    case 'float':
    case 'double':
      return (rng() * 1000) - 500;
    default:
      return null;
  }
}

function generateRandomString(rng) {
  const words = ['Alpha', 'Beta', 'Gamma', 'Delta', 'Epsilon', 'Zeta', 'Eta', 'Theta', 'Iota', 'Kappa'];
  const count = Math.floor(rng() * 3) + 1;
  const parts = [];
  for (let i = 0; i < count; i++) {
    parts.push(words[Math.floor(rng() * words.length)]);
  }
  return parts.join('_') + '_' + Math.floor(rng() * 1000);
}

function seededRandom(seed) {
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = ((hash << 5) - hash) + seed.charCodeAt(i);
    hash |= 0;
  }

  return function() {
    hash = (hash * 1103515245 + 12345) & 0x7fffffff;
    return hash / 0x7fffffff;
  };
}

function displayBulkRecords() {
  const container = $('bulk-preview');

  if (state.bulkRecords.length === 0) {
    container.innerHTML = '<div class="empty-state"><p>No records generated</p></div>';
    return;
  }

  // Show first 100 records max
  const displayCount = Math.min(state.bulkRecords.length, 100);
  let html = '';

  for (let i = 0; i < displayCount; i++) {
    const record = state.bulkRecords[i];
    const preview = JSON.stringify(record).slice(0, 100) + (JSON.stringify(record).length > 100 ? '...' : '');

    html += `<div class="record-item">
      <div class="record-header">
        <span class="record-index">#${i + 1}</span>
      </div>
      <div class="record-preview">${preview}</div>
    </div>`;
  }

  if (state.bulkRecords.length > 100) {
    html += `<div class="record-item"><em>... and ${state.bulkRecords.length - 100} more records</em></div>`;
  }

  container.innerHTML = html;
}

function downloadBulkRecords() {
  if (state.bulkRecords.length === 0) return;

  const singleFile = $('bulk-single-file').checked;

  if (singleFile) {
    // Download as JSON array
    const json = JSON.stringify(state.bulkRecords, null, 2);
    downloadText(json, 'bulk-records.json');
  } else {
    // In a full implementation, we'd create a ZIP file
    alert('Multiple file download requires ZIP support. Downloading as single JSON file.');
    const json = JSON.stringify(state.bulkRecords, null, 2);
    downloadText(json, 'bulk-records.json');
  }
}

// =============================================================================
// Encryption Modal
// =============================================================================

function openEncryptionModal() {
  $('encryption-modal').style.display = 'flex';
}

function closeModal() {
  $('encryption-modal').style.display = 'none';
}

function generateEncryptionKey() {
  const key = crypto.getRandomValues(new Uint8Array(32));
  $('encryption-key').value = Array.from(key).map(b => b.toString(16).padStart(2, '0')).join('');
}

function saveEncryptionKey() {
  const keyHex = $('encryption-key').value;
  if (keyHex.length !== 64) {
    alert('Key must be 64 hex characters (32 bytes)');
    return;
  }

  try {
    state.encryptionKey = new Uint8Array(keyHex.match(/.{2}/g).map(b => parseInt(b, 16)));
    closeModal();
  } catch (e) {
    alert('Invalid hex key');
  }
}

// =============================================================================
// Download Helpers
// =============================================================================

function downloadText(content, filename) {
  const blob = new Blob([content], { type: 'text/plain' });
  downloadBlob(blob, filename);
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function downloadFile(path, filename) {
  try {
    const response = await fetch(path);
    const blob = await response.blob();
    downloadBlob(blob, filename);
  } catch (err) {
    console.error('Download failed:', err);
    alert('Download failed: ' + err.message);
  }
}

// =============================================================================
// Initialize
// =============================================================================

document.addEventListener('DOMContentLoaded', init);
