/**
 * Virtual Scroller for Large Datasets
 *
 * Renders only visible rows for efficient display of 10K-1M records.
 * Now includes paginated table with configurable page size.
 */

/**
 * Virtual scroller component (infinite scroll)
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
 * Paginated table with fixed page size
 */
export class PaginatedTable {
  /**
   * @param {HTMLElement} container - Container element
   * @param {Object} options - Configuration options
   * @param {Array<{key: string, label: string, width?: string, format?: function, className?: string}>} [options.columns] - Column definitions
   * @param {number} [options.pageSize=10] - Number of rows per page
   * @param {function} [options.onRowClick] - Callback for row clicks
   * @param {function} [options.onPageChange] - Callback for page changes
   */
  constructor(container, options = {}) {
    this.container = container;
    this.columns = options.columns || [];
    this.pageSize = options.pageSize || 10;
    this.onRowClick = options.onRowClick || null;
    this.onPageChange = options.onPageChange || null;

    this.data = [];
    this.currentPage = 0;
    this.totalPages = 0;

    this.setupDOM();
  }

  /**
   * Set up the DOM structure
   */
  setupDOM() {
    this.container.innerHTML = '';
    this.container.classList.add('paginated-table-container');

    // Table wrapper
    this.tableWrapper = document.createElement('div');
    this.tableWrapper.className = 'paginated-table-wrapper';

    // Table
    this.table = document.createElement('table');
    this.table.className = 'paginated-table';

    // Header
    this.thead = document.createElement('thead');
    this.table.appendChild(this.thead);

    // Body
    this.tbody = document.createElement('tbody');
    this.table.appendChild(this.tbody);

    this.tableWrapper.appendChild(this.table);
    this.container.appendChild(this.tableWrapper);

    // Pagination controls
    this.paginationWrapper = document.createElement('div');
    this.paginationWrapper.className = 'pagination-controls';
    this.container.appendChild(this.paginationWrapper);

    this.renderHeader();
    this.renderPagination();
  }

  /**
   * Set column definitions
   * @param {Array} columns
   */
  setColumns(columns) {
    this.columns = columns;
    this.renderHeader();
    this.renderPage();
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
        if (col.className) {
          th.className = col.className;
        }
        headerRow.appendChild(th);
      }
    }

    this.thead.innerHTML = '';
    this.thead.appendChild(headerRow);
  }

  /**
   * Set data and recalculate pages
   * @param {Array} records
   */
  setData(records) {
    this.data = records;
    this.totalPages = Math.ceil(records.length / this.pageSize);
    this.currentPage = 0;
    this.renderPage();
    this.renderPagination();
  }

  /**
   * Clear all data
   */
  clear() {
    this.data = [];
    this.currentPage = 0;
    this.totalPages = 0;
    this.tbody.innerHTML = '';
    this.renderPagination();
  }

  /**
   * Go to a specific page
   * @param {number} page - Page number (0-indexed)
   */
  goToPage(page) {
    if (page < 0 || page >= this.totalPages) return;
    this.currentPage = page;
    this.renderPage();
    this.renderPagination();
    if (this.onPageChange) {
      this.onPageChange(page, this.totalPages);
    }
  }

  /**
   * Get current page info
   * @returns {{ page: number, totalPages: number, start: number, end: number, total: number }}
   */
  getPageInfo() {
    const start = this.currentPage * this.pageSize;
    const end = Math.min(start + this.pageSize, this.data.length);
    return {
      page: this.currentPage,
      totalPages: this.totalPages,
      start,
      end,
      total: this.data.length,
    };
  }

  /**
   * Render current page of data
   */
  renderPage() {
    if (!this.tbody) return;

    const start = this.currentPage * this.pageSize;
    const end = Math.min(start + this.pageSize, this.data.length);

    this.tbody.innerHTML = '';

    if (this.data.length === 0) {
      const tr = document.createElement('tr');
      tr.className = 'empty-row';
      const td = document.createElement('td');
      td.colSpan = this.columns.length + 1;
      td.textContent = 'No data';
      td.className = 'empty-message';
      tr.appendChild(td);
      this.tbody.appendChild(tr);
      return;
    }

    for (let i = start; i < end; i++) {
      const record = this.data[i];
      const tr = this.renderRow(record, i);
      this.tbody.appendChild(tr);
    }
  }

  /**
   * Render a single row
   * @param {Object} record - Record data
   * @param {number} index - Global row index
   * @returns {HTMLElement}
   */
  renderRow(record, index) {
    const tr = document.createElement('tr');
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

  /**
   * Render pagination controls
   */
  renderPagination() {
    if (!this.paginationWrapper) return;

    const info = this.getPageInfo();

    this.paginationWrapper.innerHTML = '';

    if (this.data.length === 0) return;

    // Page info
    const pageInfo = document.createElement('span');
    pageInfo.className = 'page-info';
    pageInfo.textContent = `${info.start + 1}-${info.end} of ${info.total}`;

    // Navigation buttons
    const nav = document.createElement('div');
    nav.className = 'page-nav';

    // First page
    const firstBtn = document.createElement('button');
    firstBtn.className = 'page-btn';
    firstBtn.innerHTML = '⟨⟨';
    firstBtn.title = 'First page';
    firstBtn.disabled = this.currentPage === 0;
    firstBtn.addEventListener('click', () => this.goToPage(0));

    // Previous page
    const prevBtn = document.createElement('button');
    prevBtn.className = 'page-btn';
    prevBtn.innerHTML = '⟨';
    prevBtn.title = 'Previous page';
    prevBtn.disabled = this.currentPage === 0;
    prevBtn.addEventListener('click', () => this.goToPage(this.currentPage - 1));

    // Page selector
    const pageSelect = document.createElement('select');
    pageSelect.className = 'page-select';
    for (let i = 0; i < this.totalPages; i++) {
      const option = document.createElement('option');
      option.value = i;
      option.textContent = `Page ${i + 1}`;
      if (i === this.currentPage) option.selected = true;
      pageSelect.appendChild(option);
    }
    pageSelect.addEventListener('change', (e) => this.goToPage(parseInt(e.target.value)));

    // Next page
    const nextBtn = document.createElement('button');
    nextBtn.className = 'page-btn';
    nextBtn.innerHTML = '⟩';
    nextBtn.title = 'Next page';
    nextBtn.disabled = this.currentPage >= this.totalPages - 1;
    nextBtn.addEventListener('click', () => this.goToPage(this.currentPage + 1));

    // Last page
    const lastBtn = document.createElement('button');
    lastBtn.className = 'page-btn';
    lastBtn.innerHTML = '⟩⟩';
    lastBtn.title = 'Last page';
    lastBtn.disabled = this.currentPage >= this.totalPages - 1;
    lastBtn.addEventListener('click', () => this.goToPage(this.totalPages - 1));

    nav.appendChild(firstBtn);
    nav.appendChild(prevBtn);
    nav.appendChild(pageSelect);
    nav.appendChild(nextBtn);
    nav.appendChild(lastBtn);

    this.paginationWrapper.appendChild(pageInfo);
    this.paginationWrapper.appendChild(nav);
  }

  /**
   * Force re-render current page
   */
  render() {
    this.renderPage();
  }

  /**
   * Destroy and clean up
   */
  destroy() {
    this.container.innerHTML = '';
  }
}

/**
 * Table-based virtual scroller for tabular data (legacy, infinite scroll)
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
 * Create CSS styles for virtual scrolling and pagination
 * Note: Styles are now defined in styles.css for better maintainability
 * @returns {string}
 */
export function getVirtualScrollerStyles() {
  return ''; // Styles moved to styles.css
}

export default VirtualScroller;
