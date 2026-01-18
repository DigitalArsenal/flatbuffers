/**
 * Virtual Scroller for Large Datasets
 *
 * Renders only visible rows for efficient display of 10K-1M records.
 */

/**
 * Virtual scroller component
 */
export class VirtualScroller {
  /**
   * @param {HTMLElement} container - Container element
   * @param {Object} options - Configuration options
   * @param {number} [options.rowHeight=40] - Height of each row in pixels
   * @param {number} [options.bufferSize=10] - Number of extra rows to render above/below viewport
   * @param {function} [options.renderRow] - Custom row renderer function
   */
  constructor(container, options = {}) {
    this.container = container;
    this.rowHeight = options.rowHeight || 40;
    this.bufferSize = options.bufferSize || 10;
    this.customRenderRow = options.renderRow || null;

    this.data = [];
    this.visibleStart = 0;
    this.visibleEnd = 0;
    this.scrollTop = 0;

    this.setupDOM();
    this.bindEvents();
  }

  /**
   * Set up the DOM structure
   */
  setupDOM() {
    // Clear container
    this.container.innerHTML = '';
    this.container.classList.add('virtual-scroller');

    // Create scroll wrapper
    this.scrollWrapper = document.createElement('div');
    this.scrollWrapper.className = 'virtual-scroll-wrapper';

    // Create height placeholder (sets total scrollable height)
    this.heightPlaceholder = document.createElement('div');
    this.heightPlaceholder.className = 'virtual-scroll-height';

    // Create content container (holds visible rows)
    this.content = document.createElement('div');
    this.content.className = 'virtual-scroll-content';

    this.scrollWrapper.appendChild(this.heightPlaceholder);
    this.scrollWrapper.appendChild(this.content);
    this.container.appendChild(this.scrollWrapper);
  }

  /**
   * Bind scroll events
   */
  bindEvents() {
    this.scrollWrapper.addEventListener('scroll', () => {
      this.scrollTop = this.scrollWrapper.scrollTop;
      this.render();
    });

    // Resize observer for responsive updates
    if (typeof ResizeObserver !== 'undefined') {
      this.resizeObserver = new ResizeObserver(() => {
        this.render();
      });
      this.resizeObserver.observe(this.scrollWrapper);
    }
  }

  /**
   * Set the data to display
   * @param {Array} records - Array of data records
   */
  setData(records) {
    this.data = records;
    this.heightPlaceholder.style.height = `${records.length * this.rowHeight}px`;
    this.scrollWrapper.scrollTop = 0;
    this.scrollTop = 0;
    this.render();
  }

  /**
   * Clear all data
   */
  clear() {
    this.data = [];
    this.heightPlaceholder.style.height = '0';
    this.content.innerHTML = '';
  }

  /**
   * Get currently visible range
   * @returns {{ start: number, end: number, total: number }}
   */
  getVisibleRange() {
    return {
      start: this.visibleStart,
      end: this.visibleEnd,
      total: this.data.length,
    };
  }

  /**
   * Render visible rows
   */
  render() {
    if (this.data.length === 0) {
      this.content.innerHTML = '';
      return;
    }

    const viewportHeight = this.scrollWrapper.clientHeight;
    const scrollTop = this.scrollTop;

    // Calculate visible range with buffer
    const startIndex = Math.max(0, Math.floor(scrollTop / this.rowHeight) - this.bufferSize);
    const visibleCount = Math.ceil(viewportHeight / this.rowHeight) + 2 * this.bufferSize;
    const endIndex = Math.min(this.data.length, startIndex + visibleCount);

    // Only re-render if range changed significantly
    if (startIndex === this.visibleStart && endIndex === this.visibleEnd) {
      return;
    }

    this.visibleStart = startIndex;
    this.visibleEnd = endIndex;

    // Render rows
    const fragment = document.createDocumentFragment();
    for (let i = startIndex; i < endIndex; i++) {
      const row = this.renderRow(this.data[i], i);
      fragment.appendChild(row);
    }

    // Position content at correct scroll offset
    this.content.style.transform = `translateY(${startIndex * this.rowHeight}px)`;
    this.content.innerHTML = '';
    this.content.appendChild(fragment);
  }

  /**
   * Render a single row
   * @param {Object} record - Record data
   * @param {number} index - Row index
   * @returns {HTMLElement}
   */
  renderRow(record, index) {
    if (this.customRenderRow) {
      return this.customRenderRow(record, index);
    }

    const row = document.createElement('div');
    row.className = 'virtual-row';
    row.style.height = `${this.rowHeight}px`;
    row.dataset.index = index;

    // Default rendering - override with customRenderRow for real use
    row.innerHTML = `<span class="row-index">${index + 1}</span>`;

    return row;
  }

  /**
   * Scroll to a specific row
   * @param {number} index - Row index to scroll to
   */
  scrollToRow(index) {
    const targetScrollTop = index * this.rowHeight;
    this.scrollWrapper.scrollTop = targetScrollTop;
  }

  /**
   * Destroy the scroller and clean up
   */
  destroy() {
    if (this.resizeObserver) {
      this.resizeObserver.disconnect();
    }
    this.container.innerHTML = '';
  }
}

/**
 * Table-based virtual scroller for tabular data
 */
export class VirtualTable extends VirtualScroller {
  /**
   * @param {HTMLElement} container - Container element
   * @param {Object} options - Configuration options
   * @param {string[]} [options.columns] - Column definitions
   * @param {number} [options.rowHeight=36] - Height of each row in pixels
   */
  constructor(container, options = {}) {
    super(container, { ...options, rowHeight: options.rowHeight || 36 });
    this.columns = options.columns || [];
    this.onRowClick = options.onRowClick || null;
  }

  /**
   * Set column definitions
   * @param {Array<{key: string, label: string, width?: string, format?: function}>} columns
   */
  setColumns(columns) {
    this.columns = columns;
    this.renderHeader();
  }

  /**
   * Set up table-specific DOM
   */
  setupDOM() {
    this.container.innerHTML = '';
    this.container.classList.add('virtual-table-container');

    // Header table (fixed)
    this.headerTable = document.createElement('table');
    this.headerTable.className = 'virtual-table-header';
    this.thead = document.createElement('thead');
    this.headerTable.appendChild(this.thead);

    // Scroll wrapper
    this.scrollWrapper = document.createElement('div');
    this.scrollWrapper.className = 'virtual-scroll-wrapper';

    // Height placeholder
    this.heightPlaceholder = document.createElement('div');
    this.heightPlaceholder.className = 'virtual-scroll-height';

    // Body table
    this.bodyTable = document.createElement('table');
    this.bodyTable.className = 'virtual-table-body';
    this.content = document.createElement('tbody');
    this.bodyTable.appendChild(this.content);

    this.scrollWrapper.appendChild(this.heightPlaceholder);
    this.scrollWrapper.appendChild(this.bodyTable);

    this.container.appendChild(this.headerTable);
    this.container.appendChild(this.scrollWrapper);

    this.renderHeader();
  }

  /**
   * Render table header
   */
  renderHeader() {
    if (!this.thead) return;

    const headerRow = document.createElement('tr');
    headerRow.innerHTML = '<th class="row-index-header">#</th>';

    if (this.columns && Array.isArray(this.columns)) {
      for (const col of this.columns) {
        const th = document.createElement('th');
        th.textContent = col.label || col.key;
        if (col.width) {
          th.style.width = col.width;
        }
        headerRow.appendChild(th);
      }
    }

    this.thead.innerHTML = '';
    this.thead.appendChild(headerRow);
  }

  /**
   * Render a table row
   * @param {Object} record - Record data
   * @param {number} index - Row index
   * @returns {HTMLElement}
   */
  renderRow(record, index) {
    const tr = document.createElement('tr');
    tr.style.height = `${this.rowHeight}px`;
    tr.dataset.index = index;

    // Index cell
    const indexTd = document.createElement('td');
    indexTd.className = 'row-index';
    indexTd.textContent = index + 1;
    tr.appendChild(indexTd);

    // Data cells
    if (this.columns && Array.isArray(this.columns)) {
      for (const col of this.columns) {
        const td = document.createElement('td');
        let value = record[col.key];

        if (col.format) {
          value = col.format(value, record);
        }

        if (value instanceof HTMLElement) {
          td.appendChild(value);
        } else {
          td.textContent = value ?? '--';
        }

        if (col.className) {
          td.className = col.className;
        }

        tr.appendChild(td);
      }
    }

    if (this.onRowClick) {
      tr.style.cursor = 'pointer';
      tr.addEventListener('click', () => this.onRowClick(record, index));
    }

    return tr;
  }
}

/**
 * Create CSS styles for virtual scrolling
 * @returns {string}
 */
export function getVirtualScrollerStyles() {
  return `
    .virtual-scroller {
      position: relative;
      height: 100%;
      overflow: hidden;
    }

    .virtual-scroll-wrapper {
      position: relative;
      height: 100%;
      overflow-y: auto;
      overflow-x: hidden;
    }

    .virtual-scroll-height {
      position: absolute;
      top: 0;
      left: 0;
      width: 1px;
      pointer-events: none;
    }

    .virtual-scroll-content {
      position: relative;
      will-change: transform;
    }

    .virtual-row {
      display: flex;
      align-items: center;
      border-bottom: 1px solid var(--border, #e2e8f0);
      padding: 0 12px;
    }

    .virtual-row:hover {
      background: var(--bg, #f8fafc);
    }

    .row-index {
      color: var(--text-muted, #64748b);
      font-weight: 500;
      min-width: 50px;
    }

    /* Table variant */
    .virtual-table-container {
      display: flex;
      flex-direction: column;
      height: 100%;
      overflow: hidden;
    }

    .virtual-table-header {
      flex-shrink: 0;
      width: 100%;
      border-collapse: collapse;
    }

    .virtual-table-header th {
      position: sticky;
      top: 0;
      background: var(--bg, #f8fafc);
      padding: 10px 12px;
      text-align: left;
      font-weight: 600;
      border-bottom: 2px solid var(--border, #e2e8f0);
    }

    .virtual-table-header .row-index-header {
      width: 50px;
    }

    .virtual-table-body {
      width: 100%;
      border-collapse: collapse;
    }

    .virtual-table-body td {
      padding: 8px 12px;
      border-bottom: 1px solid var(--border, #e2e8f0);
      font-family: var(--font-mono, monospace);
      font-size: 0.8125rem;
    }

    .virtual-table-body tr:hover td {
      background: var(--bg, #f8fafc);
    }

    .virtual-table-body .row-index {
      width: 50px;
      color: var(--text-muted, #64748b);
    }
  `;
}

export default VirtualScroller;
