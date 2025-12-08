// Lightweight client-side table enhancer: sorting, filtering, pagination
(function () {
	const SELECTORS = {
		container: "[data-table-container]",
		table: "[data-enhanced-table]",
		search: "[data-table-search]",
		pageSize: "[data-page-size]",
		pagerInfo: "[data-pager-info]",
		pagerPrev: "[data-pager-prev]",
		pagerNext: "[data-pager-next]",
	};

	function normalize(text) {
		return (text || "").toString().toLowerCase().trim();
	}

	function getCellText(td) {
		return normalize(td?.textContent || "");
	}

	function TableEnhancer(container) {
		this.container = container;
		this.table = container.querySelector(SELECTORS.table);
		this.tbody = this.table?.querySelector("tbody");
		this.rows = Array.from(this.tbody?.querySelectorAll("tr") || []);
		this.searchInput = container.querySelector(SELECTORS.search);
		this.pageSizeSelect = container.querySelector(SELECTORS.pageSize);
		this.pagerInfo = container.querySelector(SELECTORS.pagerInfo);
		this.pagerPrev = container.querySelector(SELECTORS.pagerPrev);
		this.pagerNext = container.querySelector(SELECTORS.pagerNext);
		this.headers = Array.from(this.table?.querySelectorAll("thead th") || []);

		this.state = {
			query: "",
			sort: { colIndex: 0, dir: "asc" },
			page: 1,
			pageSize: parseInt(this.pageSizeSelect?.value || "15", 10),
		};

		this._bind();
		this._render();
	}

	TableEnhancer.prototype._bind = function () {
		if (this.searchInput) {
			this.searchInput.addEventListener("input", () => {
				this.state.query = normalize(this.searchInput.value);
				this.state.page = 1;
				this._render();
			});
		}
		if (this.pageSizeSelect) {
			this.pageSizeSelect.addEventListener("change", () => {
				this.state.pageSize = parseInt(this.pageSizeSelect.value, 10) || 15;
				this.state.page = 1;
				this._render();
			});
		}
		if (this.pagerPrev) {
			this.pagerPrev.addEventListener("click", (e) => {
				e.preventDefault();
				if (this.state.page > 1) {
					this.state.page -= 1;
					this._render();
				}
			});
		}
		if (this.pagerNext) {
			this.pagerNext.addEventListener("click", (e) => {
				e.preventDefault();
				this.state.page += 1;
				this._render();
			});
		}
		// Sorting
		this.headers.forEach((th, idx) => {
			const sortable = th.hasAttribute("data-sortable");
			if (!sortable) return;
			th.style.cursor = "pointer";
			th.setAttribute("role", "button");
			th.addEventListener("click", () => {
				if (this.state.sort.colIndex === idx) {
					this.state.sort.dir = this.state.sort.dir === "asc" ? "desc" : "asc";
				} else {
					this.state.sort = { colIndex: idx, dir: "asc" };
				}
				this._render();
			});
		});
	};

	TableEnhancer.prototype._filtered = function () {
		if (!this.state.query) return this.rows.slice();
		const q = this.state.query;
		return this.rows.filter((tr) => {
			const tds = Array.from(tr.querySelectorAll("td"));
			return tds.some((td) => getCellText(td).includes(q));
		});
	};

	TableEnhancer.prototype._sorted = function (rows) {
		const { colIndex, dir } = this.state.sort;
		const sorted = rows.slice().sort((a, b) => {
			const aText = getCellText(a.querySelectorAll("td")[colIndex]);
			const bText = getCellText(b.querySelectorAll("td")[colIndex]);
			if (aText === bText) return 0;
			return aText > bText ? 1 : -1;
		});
		return dir === "asc" ? sorted : sorted.reverse();
	};

	TableEnhancer.prototype._paginated = function (rows) {
		const size = this.state.pageSize;
		const total = rows.length;
		const totalPages = Math.max(1, Math.ceil(total / size));
		if (this.state.page > totalPages) this.state.page = totalPages;
		const start = (this.state.page - 1) * size;
		const end = start + size;
		return {
			slice: rows.slice(start, end),
			total,
			totalPages,
			startIndex: start + 1,
			endIndex: Math.min(end, total),
		};
	};

	TableEnhancer.prototype._updateHeaderState = function () {
		this.headers.forEach((th, idx) => {
			if (!th.hasAttribute("data-sortable")) return;
			const isActive = idx === this.state.sort.colIndex;
			th.setAttribute("aria-sort", isActive ? this.state.sort.dir : "none");
			const icon = th.querySelector("[data-sort-indicator]");
			if (icon) {
				icon.textContent = isActive ? (this.state.sort.dir === "asc" ? "▲" : "▼") : "↕";
			}
		});
	};

	TableEnhancer.prototype._render = function () {
		// pipeline
		const filtered = this._filtered();
		const sorted = this._sorted(filtered);
		const page = this._paginated(sorted);

		// paint rows
		const frag = document.createDocumentFragment();
		page.slice.forEach((tr) => frag.appendChild(tr));
		this.tbody.innerHTML = "";
		this.tbody.appendChild(frag);

		// pager UI
		if (this.pagerInfo) {
			this.pagerInfo.textContent = `Showing ${page.startIndex}-${page.endIndex} of ${page.total}`;
		}
		if (this.pagerPrev) {
			this.pagerPrev.toggleAttribute("disabled", this.state.page <= 1);
		}
		if (this.pagerNext) {
			this.pagerNext.toggleAttribute("disabled", this.state.page >= page.totalPages);
		}

		this._updateHeaderState();
	};

	function initAll() {
		const containers = document.querySelectorAll(SELECTORS.container);
		containers.forEach((c) => new TableEnhancer(c));
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", initAll);
	} else {
		initAll();
	}
})();




























