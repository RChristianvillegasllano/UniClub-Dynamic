// Department -> Program dependent dropdown initializer
(function () {
	const DEPT_TO_PROGRAMS = {
		"Department of Accounting Education": [
			"Bachelor of Science in Accountancy",
			"Bachelor of Science in Management Accounting",
		],
		"Department of Arts and Sciences Education": [
			"Bachelor of Arts Major in English Language",
			"Bachelor of Science in Psychology",
		],
		"Department of Business Administration Education": [
			"Bachelor of Science in Business Administration - Financial Management",
			"Bachelor of Science in Business Administration - Human Resource Management",
			"Bachelor of Science in Business Administration - Marketing Management",
		],
		"Department of Computing Education": [
			"Bachelor of Science in Information Technology",
			"Bachelor of Science in Computer Science",
		],
		"Department of Criminal Justice Education": [
			"Bachelor of Science in Criminology",
		],
		"Department of Engineering Education": [
			"Bachelor of Science in Computer Engineering",
			"Bachelor of Science in Electrical Engineering",
			"Bachelor of Science in Electronics & Communications Engineering",
		],
		"Department of Hospitality Education": [
			"Bachelor of Science in Hospitality Management",
			"Bachelor of Science in Tourism Management",
		],
		"Department of Teacher Education": [
			"Bachelor of Elementary Education",
			"Bachelor of Physical Education",
			"Bachelor of Secondary Education - Major in English",
			"Bachelor of Secondary Education - Major in Filipino",
			"Bachelor of Secondary Education - Major in General Science",
			"Bachelor of Secondary Education - Major in Mathematics",
			"Bachelor of Secondary Education - Major in Social Studies",
		],
	};
	const ALL_PROGRAMS = Array.from(
		new Set(Object.values(DEPT_TO_PROGRAMS).flat())
	);

	function parseCurrentSelection(programSelect) {
		if (programSelect.multiple) {
			const raw = programSelect.dataset.current;
			if (raw) {
				try {
					const parsed = JSON.parse(raw);
					return Array.isArray(parsed) ? parsed : [];
				} catch {
					return [];
				}
			}
			return Array.from(programSelect.selectedOptions)
				.map((opt) => opt.value)
				.filter(Boolean);
		}
		return programSelect.dataset.current || programSelect.value;
	}

	function toggleLockNote(select, locked) {
		const noteSelector = select.dataset.lockNote;
		if (!noteSelector) return;
		const note = document.querySelector(noteSelector);
		if (!note) return;
		if (locked) {
			note.classList.remove("hidden");
		} else {
			note.classList.add("hidden");
		}
	}

	function registerSubmitUnlock(select) {
		const form = select.form;
		if (!form) return;
		if (form.dataset.deptProgramUnlockAttached === "true") return;
		form.addEventListener("submit", () => {
			form
				.querySelectorAll("[data-program-locked='true']")
				.forEach((lockedSelect) => {
					lockedSelect.disabled = false;
				});
		});
		form.dataset.deptProgramUnlockAttached = "true";
	}

	function toggleLockState(select, locked) {
		const hiddenId = select.dataset.lockHiddenId;
		select.dataset.programLocked = locked ? "true" : "false";
		if (locked) {
			select.disabled = true;
			select.classList.add("opacity-60", "cursor-not-allowed");
			registerSubmitUnlock(select);
			if (!hiddenId) {
				const hidden = document.createElement("input");
				hidden.type = "hidden";
				hidden.name = select.name;
				hidden.value = "__ALL__";
				const id = `locked-${select.name}-${Math.random()
					.toString(36)
					.slice(2)}`;
				hidden.id = id;
				select.parentNode.appendChild(hidden);
				select.dataset.lockHiddenId = id;
			}
		} else {
			select.disabled = false;
			select.classList.remove("opacity-60", "cursor-not-allowed");
			if (hiddenId) {
				const hidden = document.getElementById(hiddenId);
				if (hidden) hidden.remove();
				delete select.dataset.lockHiddenId;
			}
		}
		toggleLockNote(select, locked);
	}

	function selectAllProgramOptions(select) {
		Array.from(select.options).forEach((opt) => {
			if (!opt.value || opt.value === "__ALL__") {
				opt.selected = false;
			} else {
				opt.selected = true;
			}
		});
	}

	function getProgramsForDepartment(value) {
		if (!value) return [];
		if (value === "All Departments") return ALL_PROGRAMS;
		return DEPT_TO_PROGRAMS[value] || [];
	}

	function populatePrograms(programSelect, departmentValue, currentValue) {
		const isMultiple = programSelect.multiple;
		const allowAll = programSelect.dataset.allowAll === "true";
		const allowDeptAll = programSelect.dataset.allowDeptAll === "true";
		const allDeptValue = programSelect.dataset.allDeptValue || "__ALL__";
		const isAllDepartmentSelected =
			allowDeptAll && departmentValue === allDeptValue;
		// Preserve a leading placeholder only for single-selects
		let leadingLabel = null;
		if (!isMultiple) {
			const firstOptionText =
				programSelect.options.length > 0 ? programSelect.options[0].textContent : "Select Program";
			const isAll = /All Programs/i.test(firstOptionText);
			const isSelect = /Select Program/i.test(firstOptionText);
			leadingLabel = isAll ? "All Programs" : isSelect ? "Select Program" : null;
		}

		while (programSelect.firstChild) programSelect.removeChild(programSelect.firstChild);

		if (leadingLabel) {
			const opt = document.createElement("option");
			opt.value = "";
			opt.textContent = leadingLabel;
			programSelect.appendChild(opt);
		}

		if (allowAll) {
			const allOption = document.createElement("option");
			allOption.value = "__ALL__";
			allOption.textContent = "All Programs (select all)";
			allOption.dataset.selectAllOption = "true";
			programSelect.appendChild(allOption);
		}

		const programs = isAllDepartmentSelected
			? ALL_PROGRAMS
			: getProgramsForDepartment(departmentValue);
		programs.forEach((p) => {
			const opt = document.createElement("option");
			opt.value = p;
			opt.textContent = p;
			programSelect.appendChild(opt);
		});

		if (isMultiple) {
			const selections = Array.isArray(currentValue) ? new Set(currentValue) : new Set();
			Array.from(programSelect.options).forEach((opt) => {
				if (opt.value && selections.has(opt.value)) {
					opt.selected = true;
				}
			});
		} else {
			// Restore selection if still valid, else reset to empty
			if (currentValue === "__ALL__" && allowAll) {
				programSelect.value = "__ALL__";
			} else if (currentValue && programs.includes(currentValue)) {
				programSelect.value = currentValue;
			} else {
				programSelect.value = "";
			}
		}
		if (isMultiple && isAllDepartmentSelected) {
			selectAllProgramOptions(programSelect);
		}

		const shouldLock =
			allowDeptAll && isAllDepartmentSelected;
		if (shouldLock) {
			programSelect.value = "__ALL__";
		}
		toggleLockState(programSelect, shouldLock);

		// Clear cached value once applied
		if (programSelect.dataset) {
			programSelect.dataset.current = "";
		}
		// Trigger change for any cascading logic
		const event = new Event("change", { bubbles: true });
		programSelect.dispatchEvent(event);
	}

	function initPair(container) {
		const dept = container.querySelector("[data-dept-select]");
		const prog = container.querySelector("[data-program-select]");
		if (!dept || !prog) return;
		const allDeptValue = dept.dataset.allValue || "__ALL__";
		if (dept.dataset.allowAll === "true") {
			prog.dataset.allowDeptAll = "true";
			prog.dataset.allDeptValue = allDeptValue;
		}

		function refresh() {
			const currentProgram = parseCurrentSelection(prog);
			populatePrograms(prog, dept.value, currentProgram);
		}

		// Initialize once after DOM is ready
		refresh();
		// Update on department change
		dept.addEventListener("change", refresh);
	}

	function initAll() {
		// Each form or filter section can be a container
		const containers = document.querySelectorAll("[data-dept-program]");
		containers.forEach(initPair);
	}

	if (document.readyState === "loading") {
		document.addEventListener("DOMContentLoaded", initAll);
	} else {
		initAll();
	}
})();


