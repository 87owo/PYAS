document.addEventListener('DOMContentLoaded', () => {
    let currentLang = "english_switch";
    let isScanning = false;
    let isFirstLaunch = false;

    const { dict, langMap } = window.AppI18n;

    const themes = {
        "white_switch": { "--bg-window": "245, 245, 247", "--bg-nav": "255, 255, 255", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(0,0,0,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--border-color":"210, 210, 215", "--accent-color":"0, 122, 255", "--accent-alpha":"rgba(0, 122, 255, 0.1)", "--accent-shadow":"rgba(0, 122, 255, 0.2)", "--accent-hover":"rgba(0, 122, 255, 0.3)" },
        "black_switch": { "--bg-window": "0, 0, 0", "--bg-nav": "28, 28, 30", "--bg-panel": "28, 28, 30", "--bg-hover": "rgba(255,255,255,0.1)", "--text-primary": "245, 245, 247", "--text-secondary": "134, 134, 139", "--border-color":"44, 44, 46", "--accent-color":"10, 132, 255", "--accent-alpha":"rgba(10, 132, 255, 0.1)", "--accent-shadow":"rgba(10, 132, 255, 0.2)", "--accent-hover":"rgba(10, 132, 255, 0.3)" },
        "red_switch": { "--bg-window": "253, 246, 246", "--bg-nav": "255, 240, 240", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(255,59,48,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--border-color":"250, 220, 220", "--accent-color":"255, 59, 48", "--accent-alpha":"rgba(255, 59, 48, 0.1)", "--accent-shadow":"rgba(255, 59, 48, 0.2)", "--accent-hover":"rgba(255, 59, 48, 0.3)" },
        "yellow_switch": { "--bg-window": "254, 251, 243", "--bg-nav": "255, 248, 230", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(255,149,0,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--border-color":"250, 240, 215", "--accent-color":"255, 149, 0", "--accent-alpha":"rgba(255, 149, 0, 0.1)", "--accent-shadow":"rgba(255, 149, 0, 0.2)", "--accent-hover":"rgba(255, 149, 0, 0.3)" },
        "green_switch": { "--bg-window": "246, 253, 248", "--bg-nav": "235, 250, 240", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(52,199,89,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--border-color":"220, 240, 225", "--accent-color":"52, 199, 89", "--accent-alpha":"rgba(52, 199, 89, 0.1)", "--accent-shadow":"rgba(52, 199, 89, 0.2)", "--accent-hover":"rgba(52, 199, 89, 0.3)" },
        "blue_switch": { "--bg-window": "246, 249, 253", "--bg-nav": "235, 244, 255", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(0,122,255,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--border-color":"220, 230, 250", "--accent-color":"0, 122, 255", "--accent-alpha":"rgba(0, 122, 255, 0.1)", "--accent-shadow":"rgba(0, 122, 255, 0.2)", "--accent-hover":"rgba(0, 122, 255, 0.3)" }
    };

    const cols = {
        log: [
            {key: 'time_str', label: '日期', flex: 1.5},
            {key: 'level', label: '類型', flex: 0.8},
            {key: 'action', label: '功能', flex: 1.2},
            {key: 'source', label: '路徑', flex: 3}
        ],
        process: [
            {key: 'name', label: '名稱', flex: 1.5},
            {key: 'pid', label: 'PID', flex: 0.5},
            {key: 'path', label: '路徑', flex: 3}
        ],
        virus: [
            {key: 'label', label: '類型', flex: 1},
            {key: 'path', label: '路徑', flex: 3}
        ],
        pathOnly: [
            {key: 'path', label: '路徑', flex: 1}
        ],
        junk: [
            {key: 'path', label: '路徑', flex: 3},
            {key: 'sizeStr', label: '大小', flex: 1}
        ],
        popup: [
            {key: 'exe', label: '程式', flex: 1},
            {key: 'class', label: '類別', flex: 1},
            {key: 'title', label: '標題', flex: 2}
        ],
        repair: [
            {key: 'display', label: '修復項目', flex: 1}
        ]
    };

    const getMsg = (key) => (dict[currentLang] || dict["english_switch"])[key] || key;

    function buildCustomSelectElement(select) {
        select.style.display = 'none';
        const wrapper = document.createElement('div');
        wrapper.className = 'custom-select-wrapper';
        
        const trigger = document.createElement('div');
        trigger.className = 'custom-select-trigger';
        const triggerText = document.createElement('span');
        triggerText.className = 'custom-select-text';
        
        const selectedOpt = select.options[select.selectedIndex];
        if (selectedOpt) {
            triggerText.textContent = selectedOpt.textContent;
            if (selectedOpt.hasAttribute('data-i18n')) triggerText.setAttribute('data-i18n', '');
            if (selectedOpt.hasAttribute('data-origin-text')) triggerText.dataset.originText = selectedOpt.dataset.originText;
        }
        
        const icon = document.createElement('div');
        icon.className = 'custom-select-icon';
        icon.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>`;
        
        trigger.appendChild(triggerText);
        trigger.appendChild(icon);
        
        const optionsContainer = document.createElement('ul');
        optionsContainer.className = 'custom-select-options';

        const phantom = document.createElement('div');
        phantom.className = 'custom-select-phantom';
        phantom.setAttribute('aria-hidden', 'true');
        
        Array.from(select.options).forEach(option => {
            if (option.disabled) return;
            
            const li = document.createElement('li');
            li.className = 'custom-select-option';
            li.textContent = option.textContent;
            li.dataset.value = option.value;
            if (option.hasAttribute('data-i18n')) li.setAttribute('data-i18n', '');
            if (option.hasAttribute('data-origin-text')) li.dataset.originText = option.dataset.originText;
            if (option.selected) li.classList.add('selected');
            
            li.addEventListener('click', (e) => {
                e.stopPropagation();
                select.value = option.value;
                triggerText.textContent = li.textContent;
                if (li.hasAttribute('data-origin-text')) {
                    triggerText.dataset.originText = li.dataset.originText;
                }
                wrapper.classList.remove('open');
                optionsContainer.querySelectorAll('.custom-select-option').forEach(el => el.classList.remove('selected'));
                li.classList.add('selected');
                select.dispatchEvent(new Event('change'));
            });
            optionsContainer.appendChild(li);

            const phantomSpan = document.createElement('span');
            phantomSpan.textContent = option.textContent;
            if (option.hasAttribute('data-i18n')) phantomSpan.setAttribute('data-i18n', '');
            if (option.hasAttribute('data-origin-text')) phantomSpan.dataset.originText = option.dataset.originText;
            phantom.appendChild(phantomSpan);
        });
        
        wrapper.appendChild(phantom);
        wrapper.appendChild(trigger);
        wrapper.appendChild(optionsContainer);
        select.parentNode.insertBefore(wrapper, select.nextSibling);
        
        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = wrapper.classList.contains('open');
            document.querySelectorAll('.custom-select-wrapper').forEach(w => w.classList.remove('open'));
            if (!isOpen) wrapper.classList.add('open');
        });
    }

    function initCustomSelects() {
        document.querySelectorAll('select.modern-select').forEach(select => {
            buildCustomSelectElement(select);
        });
        
        document.addEventListener('click', () => {
            document.querySelectorAll('.custom-select-wrapper').forEach(w => w.classList.remove('open'));
        });
    }

    initCustomSelects();

    document.querySelectorAll("[data-i18n]").forEach(el => { el.dataset.originText = el.textContent.trim(); });
    document.querySelectorAll("[data-i18n-placeholder]").forEach(el => { el.dataset.originPlaceholder = el.getAttribute('placeholder'); });
    document.querySelectorAll("option[data-i18n]").forEach(el => { el.dataset.originText = el.textContent.trim(); });

    const translateText = (lang) => {
        currentLang = lang;
        const currentDict = dict[lang] || dict["english_switch"];
        document.querySelectorAll("[data-i18n]").forEach(el => {
            const originText = el.dataset.originText;
            el.textContent = currentDict[originText] || originText;
        });
        document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
            const originText = el.dataset.originPlaceholder;
            el.setAttribute('placeholder', currentDict[originText] || originText);
        });
        document.querySelectorAll('.manage-widget, .virus-widget').forEach(widget => {
            if (widget.renderData) widget.renderData();
        });
        document.documentElement.lang = langMap[currentLang] || "en";

        const progressText = document.getElementById('progress_text');
        if (progressText && progressText.dataset.dynamicMsg) {
            try {
                const msgs = JSON.parse(progressText.dataset.dynamicMsg);
                if (msgs[lang]) {
                    progressText.textContent = msgs[lang];
                }
            } catch (e) {}
        }
    };

    const applyTheme = (theme) => {
        const themeVars = themes[theme];
        if (themeVars) {
            for (const [key, value] of Object.entries(themeVars)) {
                document.documentElement.style.setProperty(key, value.startsWith("rgba") ? value : `rgb(${value})`);
            }
        }
    };

    function updateCustomSelectUI(selectId, val) {
        const select = document.getElementById(selectId);
        if (!select) return;
        select.value = val;
        let wrapper = select.nextElementSibling;
        if (wrapper && wrapper.classList.contains('custom-select-wrapper')) {
            const triggerText = wrapper.querySelector('.custom-select-text');
            const selectedOpt = select.options[select.selectedIndex];
            if (selectedOpt) {
                triggerText.textContent = selectedOpt.textContent;
                if (selectedOpt.hasAttribute('data-origin-text')) {
                    triggerText.dataset.originText = selectedOpt.dataset.originText;
                }
            }
            wrapper.querySelectorAll('.custom-select-option').forEach(el => {
                el.classList.toggle('selected', el.dataset.value === val);
            });
        }
    }

    function renderDataGrid(containerSelector, dataList, columns, valKey, defaultChecked = false) {
        const widget = document.querySelector(`${containerSelector} .manage-widget`) || document.querySelector(`${containerSelector} .virus-widget`);
        const listUl = document.querySelector(`${containerSelector} .manage-list`) || document.querySelector(`${containerSelector} .virus-list`);
        const searchInput = document.querySelector(`${containerSelector} .search-box input`);
        if (!widget || !listUl) return;

        const escapeHtml = (unsafe) => {
            if (typeof unsafe !== 'string') return unsafe;
            return unsafe
                 .replace(/&/g, "&amp;")
                 .replace(/</g, "&lt;")
                 .replace(/>/g, "&gt;")
                 .replace(/"/g, "&quot;")
                 .replace(/'/g, "&#039;");
        };

        const isInit = !widget.gridState;

        if (isInit) {
            let containerWidth = widget.clientWidth || 800;
            let availableWidth = Math.max(containerWidth - 60 - (columns.length * 16), 400); 
            let totalFlex = columns.reduce((sum, c) => sum + (c.flex || 1), 0);
            
            widget.gridState = { 
                sortKey: columns[0]?.key || '', 
                sortAsc: true, 
                filterText: "",
                colWidths: columns.map(c => Math.max(((c.flex || 1) / totalFlex) * availableWidth, 60)),
                checkedSet: new Set()
            };
            
            widget.gridState.colWidths.forEach((w, idx) => {
                widget.style.setProperty(`--col-${idx}`, `${w}px`);
            });

            const header = document.createElement('div');
            header.className = 'manage-list-header';
            widget.insertBefore(header, widget.firstChild);

            widget.buildHeader = () => {
                const headerColsHtml = columns.map((col, idx) => 
                    `<div class="col-header" data-key="${col.key}" data-idx="${idx}" style="width: var(--col-${idx}); flex: 0 0 auto;">
                        <span class="header-text" data-i18n data-origin-text="${col.label}">${getMsg(col.label)}</span>
                        <span class="sort-icon">${widget.gridState.sortKey === col.key ? (widget.gridState.sortAsc ? '▲' : '▼') : ''}</span>
                        <div class="col-resizer"></div>
                    </div>`
                ).join('');

                header.innerHTML = `
                    <input type="checkbox" class="select-all-cb" title="${getMsg('全選')}">
                    <div class="header-cols-container">${headerColsHtml}</div>
                `;

                header.querySelectorAll('.col-header').forEach(el => {
                    el.addEventListener('click', () => {
                        const key = el.dataset.key;
                        if (widget.gridState.sortKey === key) {
                            widget.gridState.sortAsc = !widget.gridState.sortAsc;
                        } else {
                            widget.gridState.sortKey = key;
                            widget.gridState.sortAsc = true;
                        }
                        widget.buildHeader(); 
                        widget.renderData(widget.gridState.filterText, false); 
                    });
                });

                header.querySelectorAll('.col-resizer').forEach(resizer => {
                    resizer.addEventListener('mousedown', (e) => {
                        e.stopPropagation();
                        const headerCell = resizer.parentElement;
                        const idx = parseInt(headerCell.dataset.idx);
                        const startX = e.clientX;
                        const startWidth = widget.gridState.colWidths[idx];

                        const onMouseMove = (moveEvent) => {
                            const newWidth = Math.max(startWidth + (moveEvent.clientX - startX), 40);
                            widget.gridState.colWidths[idx] = newWidth;
                            widget.style.setProperty(`--col-${idx}`, `${newWidth}px`);
                        };

                        const onMouseUp = () => {
                            document.body.classList.remove('resizing-active');
                            document.removeEventListener('mousemove', onMouseMove);
                            document.removeEventListener('mouseup', onMouseUp);
                        };

                        document.body.classList.add('resizing-active');
                        document.addEventListener('mousemove', onMouseMove);
                        document.addEventListener('mouseup', onMouseUp);
                    });
                    resizer.addEventListener('click', (e) => e.stopPropagation());
                });

                const selectAllCb = header.querySelector('.select-all-cb');
                if (selectAllCb) {
                    selectAllCb.addEventListener('change', (e) => {
                        const isChecked = e.target.checked;
                        listUl.querySelectorAll('.manage-list-item input[type="checkbox"]').forEach(cb => {
                            cb.checked = isChecked;
                            if (isChecked) {
                                widget.gridState.checkedSet.add(cb.value);
                            } else {
                                widget.gridState.checkedSet.delete(cb.value);
                            }
                            if (containerSelector === '#scan_window') {
                                virusState.set(cb.value, isChecked);
                            }
                        });
                        if (containerSelector === '#scan_window' && typeof checkVirusListEmpty === 'function') {
                            checkVirusListEmpty();
                        }
                    });
                }
            };
            
            widget.buildHeader();

            listUl.addEventListener('click', (e) => {
                const li = e.target.closest('.manage-list-item');
                if (!li) return;
                
                const cb = li.querySelector('input[type="checkbox"]');
                if (e.target.tagName !== 'INPUT') {
                    cb.checked = !cb.checked;
                }
                
                if (cb.checked) {
                    widget.gridState.checkedSet.add(cb.value);
                } else {
                    widget.gridState.checkedSet.delete(cb.value);
                }
                
                if (containerSelector === '#scan_window') {
                    virusState.set(cb.value, cb.checked);
                    if (typeof checkVirusListEmpty === 'function') checkVirusListEmpty();
                }
                
                if (typeof widget.updateSelectAllState === 'function') {
                    widget.updateSelectAllState();
                }
            });

            if (searchInput) {
                searchInput.addEventListener('input', (e) => widget.renderData(e.target.value, false));
            }
        }

        const state = widget.gridState;

        widget.renderData = (filterText = state.filterText, resetDataCheck = false) => {
            state.filterText = filterText;
            
            if (resetDataCheck) {
                state.checkedSet.clear();
                dataList.forEach(item => {
                    if (defaultChecked) state.checkedSet.add(String(item[valKey]));
                });
            } else {
                const validKeys = new Set(dataList.map(item => String(item[valKey])));
                for (const val of state.checkedSet) {
                    if (!validKeys.has(val)) {
                        state.checkedSet.delete(val);
                    }
                }

                if (state.checkedSet.size === 0 && defaultChecked && dataList.length > 0) {
                    const hasAnyCheckedInDOM = listUl.querySelector('input[type="checkbox"]:checked');
                    if (!hasAnyCheckedInDOM) {
                        dataList.forEach(item => state.checkedSet.add(String(item[valKey])));
                    }
                }
            }

            const header = widget.querySelector('.manage-list-header');
            const selectAllCb = header ? header.querySelector('.select-all-cb') : null;
            if (selectAllCb) selectAllCb.disabled = dataList.length === 0;

            let displayData = dataList.filter(item => {
                if (!filterText) return true;
                const ft = filterText.toLowerCase();
                return columns.some(col => String(item[col.key] || '').toLowerCase().includes(ft));
            });

            displayData.sort((a, b) => {
                let valA = a[state.sortKey] ?? '';
                let valB = b[state.sortKey] ?? '';

                if (state.sortKey === 'sizeStr' && 'size' in a && 'size' in b) {
                    return state.sortAsc ? a.size - b.size : b.size - a.size;
                }

                let numA = parseFloat(valA);
                let numB = parseFloat(valB);
                if (!isNaN(numA) && !isNaN(numB) && String(valA).trim() !== '' && String(valB).trim() !== '') {
                    return state.sortAsc ? numA - numB : numB - numA;
                }
                return state.sortAsc ? String(valA).localeCompare(String(valB)) : String(valB).localeCompare(String(valA));
            });

            widget.updateSelectAllState = () => {
                if (!selectAllCb) return;
                const total = listUl.querySelectorAll('input[type="checkbox"]').length;
                const checked = listUl.querySelectorAll('input[type="checkbox"]:checked').length;
                selectAllCb.checked = (total > 0 && total === checked);
                selectAllCb.indeterminate = (checked > 0 && checked < total);
            };

            let htmlContent = '';
            const MAX_RENDER_ITEMS = 2000;
            const limitData = displayData.slice(0, MAX_RENDER_ITEMS);

            limitData.forEach(item => {
                const itemValStr = String(item[valKey]);
                let isChecked = false;
                
                if (containerSelector === '#scan_window') {
                    isChecked = virusState.get(itemValStr) ?? true;
                    virusState.set(itemValStr, isChecked);
                } else {
                    isChecked = state.checkedSet.has(itemValStr);
                }
                
                const checkedAttr = isChecked ? 'checked' : '';
                
                let rowColsHtml = columns.map((col, idx) => {
                    let valStr = String(item[col.key] || '');
                    return `<div class="row-col" style="width: var(--col-${idx}); flex: 0 0 auto;" title="${escapeHtml(valStr)}">${escapeHtml(valStr)}</div>`;
                }).join('');

                let escapedPath = escapeHtml(item.path || '');
                htmlContent += `
                    <li class="manage-list-item">
                        <input type="checkbox" value="${escapeHtml(itemValStr)}" ${checkedAttr} data-path="${escapedPath}">
                        <div class="manage-list-item-content">${rowColsHtml}</div>
                    </li>
                `;
            });

            if (displayData.length > MAX_RENDER_ITEMS) {
                htmlContent += `
                    <li class="manage-list-item" style="pointer-events: none; justify-content: center;">
                        <div style="color: var(--text-secondary); padding: 10px;">(資料過多，僅顯示前 ${MAX_RENDER_ITEMS} 筆以確保效能流暢)</div>
                    </li>
                `;
            }

            const scrollContainer = listUl.parentElement;
            const scrollTop = scrollContainer ? scrollContainer.scrollTop : 0;
            listUl.innerHTML = htmlContent;
            if (scrollContainer) scrollContainer.scrollTop = scrollTop;
            
            widget.updateSelectAllState();
        };

        widget.renderData(state.filterText, isInit);
    }

    function getCheckedValues(containerSelector) {
        const checkboxes = document.querySelectorAll(`${containerSelector} .manage-list-item input[type="checkbox"]:checked`);
        return Array.from(checkboxes).map(cb => cb.value);
    }

    let taskmgrTimer = null;
    let isTaskmgrActive = false;
    let currentJunkList = [];
    window.virusResults = [];

    renderDataGrid('#scan_window', window.virusResults, cols.virus, 'path', true);
    renderDataGrid('#taskmgr_window', [], cols.process, 'pid', false);
    renderDataGrid('#junk_window', [], cols.junk, 'path', true);
    renderDataGrid('#repair_window', [], cols.repair, 'value', true);
    renderDataGrid('#whitelist_window', [], cols.pathOnly, 'path', false);
    renderDataGrid('#quarantine_window', [], cols.pathOnly, 'path', false);
    renderDataGrid('#custom_protect_window', [], cols.pathOnly, 'path', false);
    renderDataGrid('#popup_window', [], cols.popup, 'value', false);
    renderDataGrid('#log_export_window', [], cols.log, 'id', true);
    
    const switchPage = (targetId) => {
        const oldActive = document.querySelector('.page.active');
        if (oldActive && oldActive.id !== targetId) {
            if (oldActive.id === 'junk_window') {
                currentJunkList = [];
                renderDataGrid('#junk_window', [], cols.junk, 'path', true);
                const searchInput = document.querySelector('#junk_window .search-box input');
                if (searchInput) searchInput.value = '';
            } else if (oldActive.id === 'repair_window') {
                renderDataGrid('#repair_window', [], cols.repair, 'value', true);
            }
        }

        document.querySelectorAll('.page').forEach(page => page.classList.remove('active'));
        document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
        const targetPage = document.getElementById(targetId);
        if (targetPage) targetPage.classList.add('active');
        const activeNav = document.querySelector(`aside .nav-btn[data-target="${targetId}"]`);
        if (activeNav) activeNav.classList.add('active');
        
        if (targetId === 'taskmgr_window') {
            isTaskmgrActive = true;
            const widget = document.querySelector('#taskmgr_window .manage-widget');
            const fetchProcs = () => {
                if (!isTaskmgrActive || !window.pywebview) return;
                const hasChecked = widget && widget.gridState && widget.gridState.checkedSet.size > 0;
                const isHovering = widget && widget.matches(':hover');
                const isMenuOpen = document.querySelector('.custom-context-menu.show') !== null;
                const isResizing = document.body.classList.contains('resizing-active');
                
                if (!hasChecked && !isHovering && !isMenuOpen && !isResizing) {
                    window.pywebview.api.get_process_list().then(procs => {
                        updateProcessList(procs);
                        if (isTaskmgrActive) taskmgrTimer = setTimeout(fetchProcs, 2000);
                    }).catch(() => {
                        if (isTaskmgrActive) taskmgrTimer = setTimeout(fetchProcs, 2000);
                    });
                } else {
                    if (isTaskmgrActive) taskmgrTimer = setTimeout(fetchProcs, 2000);
                }
            };
            fetchProcs();
        } else {
            isTaskmgrActive = false;
            if (taskmgrTimer) {
                clearTimeout(taskmgrTimer);
                taskmgrTimer = null;
            }
        }

        if (['whitelist_window', 'quarantine_window', 'popup_window', 'custom_protect_window'].includes(targetId)) {
            refreshConfigLists();
        }

        if (targetId === 'log_export_window' && window.pywebview) {
            window.pywebview.api.get_logs().then(logs => {
                const logList = logs.reverse().map(log => ({
                    time_str: `[${log.time_str}]`,
                    level: log.level,
                    action: log.action,
                    source: log.source ? log.source : '-',
                    id: log.id
                }));
                renderDataGrid('#log_export_window', logList, cols.log, 'id', true);
            });
        }
    };

    document.querySelectorAll('[data-target]').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const targetId = e.currentTarget.getAttribute('data-target');
            if (targetId) switchPage(targetId);
        });
    });

    document.getElementById('quick_scan_btn')?.addEventListener('click', () => {
        if (isScanning) return;
        switchPage('scan_window');
        if (window.pywebview) triggerScan('smart');
    });

    const scanMethodSelect = document.getElementById('scan_method_select');
    const stopBtn = document.getElementById('stop_btn');
    const progressText = document.getElementById('progress_text');
    const progressTitle = document.querySelector('#scan_window .section-title');
    const virusState = new Map();

    function rebuildCustomSelect(selectId) {
        const select = document.getElementById(selectId);
        if (!select) return;
        
        let sibling = select.nextElementSibling;
        while (sibling && sibling.classList.contains('custom-select-wrapper')) {
            const toRemove = sibling;
            sibling = sibling.nextElementSibling;
            toRemove.remove();
        }
        
        buildCustomSelectElement(select);
    }

    function changeScanSelectMode(mode) {
        if (!scanMethodSelect) return;
        scanMethodSelect.innerHTML = '';
        if (mode === 'scan') {
            scanMethodSelect.innerHTML = `
                <option value="none" selected disabled data-i18n>選擇</option>
                <option value="smart" data-i18n>智能掃描</option>
                <option value="file" data-i18n>檔案掃描</option>
                <option value="path" data-i18n>路徑掃描</option>
                <option value="full" data-i18n>全盤掃描</option>
            `;
        } else if (mode === 'action') {
            scanMethodSelect.innerHTML = `
                <option value="none" selected disabled data-i18n>選擇</option>
                <option value="delete" data-i18n>刪除項目</option>
                <option value="ignore" data-i18n>忽略項目</option>
                <option value="quarantine" data-i18n>加入隔離區</option>
                <option value="whitelist" data-i18n>加入白名單</option>
            `;
        }
        
        scanMethodSelect.querySelectorAll('option[data-i18n]').forEach(el => {
            el.dataset.originText = el.textContent.trim();
            el.textContent = getMsg(el.dataset.originText);
        });
        rebuildCustomSelect('scan_method_select');
    }

    function getScanSelectWrapper() {
        if (!scanMethodSelect) return null;
        const w = scanMethodSelect.nextElementSibling;
        return (w && w.classList.contains('custom-select-wrapper')) ? w : null;
    }

    function handleVirusActions(action) {
        if (!window.pywebview) return;
        const paths = Array.from(virusState.entries()).filter(([_, isChecked]) => isChecked).map(([path, _]) => path);

        if (paths.length === 0) {
            updateCustomSelectUI('scan_method_select', 'none');
            return;
        }

        const wrapper = getScanSelectWrapper();
        if (wrapper) wrapper.style.pointerEvents = 'none';

        const finalizeAction = () => {
            const curWrapper = getScanSelectWrapper();
            if (curWrapper) curWrapper.style.pointerEvents = '';
            checkVirusListEmpty();
        };

        const removeListItems = (removedPaths) => {
            const removedSet = new Set(removedPaths);
            removedPaths.forEach(p => virusState.delete(p));
            
            for (let i = window.virusResults.length - 1; i >= 0; i--) {
                if (removedSet.has(window.virusResults[i].path)) {
                    window.virusResults.splice(i, 1);
                }
            }
            
            const widget = document.querySelector('#scan_window .virus-widget');
            if (widget && typeof widget.renderData === 'function') {
                widget.renderData(widget.gridState.filterText, false);
            }
        };

        if (action === 'delete') {
            window.pywebview.api.solve_scan(paths).then((deletedPaths) => {
                removeListItems(deletedPaths);
                finalizeAction();
            });
        } else if (action === 'ignore') {
            window.pywebview.api.remove_virus_result(paths).then(() => {
                removeListItems(paths);
                finalizeAction();
            });
        } else if (action === 'quarantine' || action === 'whitelist') {
            const listKey = action === 'quarantine' ? 'quarantine' : 'white_list';
            window.pywebview.api.manage_named_list(listKey, paths, 'add').then(() => {
                window.pywebview.api.remove_virus_result(paths).then(() => {
                    removeListItems(paths);
                    finalizeAction();
                });
            });
        }
    }

    function checkVirusListEmpty() {
        updateCustomSelectUI('scan_method_select', 'none');
        if (virusState.size === 0) {
            changeScanSelectMode('scan');
            if (progressTitle) {
                progressTitle.setAttribute('data-i18n', '');
                progressTitle.dataset.originText = "病毒掃描";
                progressTitle.textContent = getMsg("病毒掃描");
            }
            if (progressText) {
                progressText.setAttribute('data-i18n', '');
                progressText.removeAttribute('data-dynamic-msg');
                progressText.dataset.originText = "此選項可以選擇進階掃描方式";
                progressText.textContent = getMsg("此選項可以選擇進階掃描方式");
            }
        }
    }

    let virusRenderTimeout = null;
    window.addVirusResult = (label, path) => {
        if (!virusState.has(path)) {
            window.virusResults.push({ label: label, path: path });
            virusState.set(path, true);
            
            const widget = document.querySelector('#scan_window .virus-widget');
            if (widget && typeof widget.renderData === 'function') {
                if (virusRenderTimeout) clearTimeout(virusRenderTimeout);
                virusRenderTimeout = setTimeout(() => {
                    widget.renderData(widget.gridState.filterText, false);
                }, 50);
            }
        }
    };

    window.updateScanProgress = (path) => {
        if (progressTitle) {
            progressTitle.setAttribute('data-i18n', '');
            progressTitle.dataset.originText = "正在掃描";
            progressTitle.textContent = getMsg("正在掃描");
        }
        if (progressText) {
            progressText.removeAttribute('data-i18n');
            progressText.removeAttribute('data-dynamic-msg');
            progressText.textContent = path;
        }
    };

    window.updateDeleteProgress = (path) => {
        if (progressTitle) {
            progressTitle.setAttribute('data-i18n', '');
            progressTitle.dataset.originText = "正在刪除";
            progressTitle.textContent = getMsg("正在刪除");
        }
        if (progressText) {
            progressText.removeAttribute('data-i18n');
            progressText.removeAttribute('data-dynamic-msg');
            progressText.textContent = path;
        }
    };

    window.finishScan = (msgData, count) => {
        isScanning = false;
        if (progressTitle) {
            progressTitle.setAttribute('data-i18n', '');
            progressTitle.dataset.originText = "病毒掃描";
            progressTitle.textContent = getMsg("病毒掃描");
        }
        if (progressText) {
            progressText.removeAttribute('data-i18n');
            if (typeof msgData === 'object' && msgData !== null) {
                progressText.dataset.dynamicMsg = JSON.stringify(msgData);
                progressText.textContent = msgData[currentLang] || msgData["english_switch"];
            } else {
                progressText.removeAttribute('data-dynamic-msg');
                progressText.textContent = msgData;
            }
        }
        stopBtn.classList.add('hidden');
        scanMethodSelect.classList.remove('hidden');
        
        if (count > 0) {
            changeScanSelectMode('action');
        } else {
            changeScanSelectMode('scan');
        }
        updateCustomSelectUI('scan_method_select', 'none');
    };

    function triggerScan(method) {
        if (!window.pywebview) return;
        isScanning = true;
        virusState.clear();
        window.virusResults = [];
        renderDataGrid('#scan_window', window.virusResults, cols.virus, 'path', true);
        changeScanSelectMode('scan');
        scanMethodSelect.classList.add('hidden');
        stopBtn.classList.remove('hidden');
        stopBtn.disabled = false;
        if (progressTitle) {
            progressTitle.setAttribute('data-i18n', '');
            progressTitle.dataset.originText = "正在掃描";
            progressTitle.textContent = getMsg("正在掃描");
        }
        if (progressText) {
            progressText.setAttribute('data-i18n', '');
            progressText.removeAttribute('data-dynamic-msg');
            progressText.dataset.originText = "正在初始化中";
            progressText.textContent = getMsg("正在初始化中");
        }
        window.pywebview.api.trigger_scan(method);
    }

    scanMethodSelect?.addEventListener('change', () => {
        const val = scanMethodSelect.value;
        if (val === 'none') return;

        if (!isScanning) {
            if (['smart', 'file', 'path', 'full'].includes(val)) {
                triggerScan(val);
            } else if (['delete', 'ignore', 'quarantine', 'whitelist'].includes(val)) {
                handleVirusActions(val);
            }
        }
    });

    stopBtn?.addEventListener('click', () => {
        if (window.pywebview) window.pywebview.api.stop_scan();
        stopBtn.disabled = true;
    });

    document.getElementById('theme_select')?.addEventListener('change', (e) => {
        applyTheme(e.target.value);
        if (window.pywebview) window.pywebview.api.update_config('theme', e.target.value);
    });

    document.getElementById('lang_select')?.addEventListener('change', (e) => {
        translateText(e.target.value);
        if (window.pywebview) window.pywebview.api.update_config('language', e.target.value);
    });

    window.revertSwitch = (switchKey) => {
        // No-op: Async handler in toggle switch automatically reverts based on backend response.
    };

    document.querySelectorAll('.toggle-switch input').forEach((toggle, index) => {
        toggle.addEventListener('change', async (e) => {
            const switchMap = ["process_switch", "document_switch", "system_switch", "driver_switch", "network_switch", "sensitive_switch", "extension_switch", "cloud_switch", "context_switch"];
            const key = switchMap[index];
            if (window.pywebview && key) {
                toggle.disabled = true;
                try {
                    const result = await window.pywebview.api.update_config(key, e.target.checked);
                    if (result !== undefined && result !== null) {
                        toggle.checked = result;
                    }
                } catch (err) {
                    toggle.checked = !e.target.checked;
                } finally {
                    toggle.disabled = false;
                }
            }
        });
    });

    window.triggerContextScan = (path) => {
        if (isScanning) return;
        switchPage('scan_window');
        if (window.pywebview) {
            isScanning = true;
            virusState.clear();
            window.virusResults = [];
            renderDataGrid('#scan_window', window.virusResults, cols.virus, 'path', true);
            scanMethodSelect.classList.add('hidden');
            stopBtn.classList.remove('hidden');
            stopBtn.disabled = false;
            changeScanSelectMode('scan');
            if (progressTitle) {
                progressTitle.setAttribute('data-i18n', '');
                progressTitle.dataset.originText = "正在掃描";
                progressTitle.textContent = getMsg("正在掃描");
            }
            if (progressText) {
                progressText.setAttribute('data-i18n', '');
                progressText.removeAttribute('data-dynamic-msg');
                progressText.dataset.originText = "正在初始化中";
                progressText.textContent = getMsg("正在初始化中");
            }
            window.pywebview.api.start_scan([path]);
        }
    };

    window.addEventListener('pywebviewready', () => {
        window.pywebview.api.get_config().then(async cfg => {
            const theme = cfg.theme || "white_switch";
            const lang = cfg.language || "english_switch";
            applyTheme(theme);
            translateText(lang);
            updateCustomSelectUI('theme_select', theme);
            updateCustomSelectUI('lang_select', lang);

            const switchMap = ["process_switch", "document_switch", "system_switch", "driver_switch", "network_switch", "sensitive_switch", "extension_switch", "cloud_switch", "context_switch"];
            
            isFirstLaunch = cfg.first_launch;
            
            if (isFirstLaunch) {
                document.querySelectorAll('.toggle-switch input').forEach(toggle => {
                    toggle.checked = false;
                    toggle.disabled = true;
                });
            } else {
                document.querySelectorAll('.toggle-switch input').forEach((toggle, index) => {
                    if (switchMap[index]) {
                        toggle.checked = !!cfg[switchMap[index]];
                    }
                });
            }
        });
        window.pywebview.api.init_ui_ready();
    });

    window.onEngineReady = async () => {
        if (!isFirstLaunch) return;
        
        const switchMap = ["process_switch", "document_switch", "system_switch", "driver_switch", "network_switch", "sensitive_switch", "extension_switch", "cloud_switch", "context_switch"];
        
        await window.pywebview.api.update_config("first_launch", false);

        const sequence = [
            "cloud_switch", 
            "process_switch", "document_switch", "system_switch", "network_switch",
            "driver_switch"
        ];

        for (const key of sequence) {
            const index = switchMap.indexOf(key);
            if (index !== -1) {
                const toggle = document.querySelectorAll('.toggle-switch input')[index];
                if (toggle) {
                    toggle.checked = true;
                    try {
                        const result = await window.pywebview.api.update_config(key, true);
                        if (result !== undefined && result !== null) {
                            toggle.checked = result;
                        }
                    } catch (e) {
                        toggle.checked = false;
                    } finally {
                        toggle.disabled = false;
                    }
                    await new Promise(r => setTimeout(r, 200));
                }
            }
        }
        
        document.querySelectorAll('.toggle-switch input').forEach(toggle => {
            toggle.disabled = false;
        });
        
        isFirstLaunch = false;
    };

    window.updateLogs = (entry) => {
        const logWidget = document.querySelector('.log-text');
        if (logWidget) {
            let parts = [`[${entry.time_str}]`, entry.level, entry.action];
            if (entry.source) parts.push(`Src: ${entry.source}`);
            if (entry.target) parts.push(`Tgt: ${entry.target}`);
            if (entry.code) parts.push(`Code: ${entry.code}`);
            if (entry.pid) parts.push(`PID: ${entry.pid}`);
            if (entry.hash) parts.push(`Hash: ${entry.hash}`);
            if (entry.detail) parts.push(`Detail: ${entry.detail}`);
            if (entry.operate !== null) parts.push(`Op: ${entry.operate}`);
            parts.push(`Success: ${entry.success}`);
            
            let val = logWidget.value + parts.join(' | ') + '\n';
            if (val.length > 20000) {
                val = val.substring(val.length - 15000);
                val = val.substring(val.indexOf('\n') + 1);
            }
            
            logWidget.value = val;
            logWidget.scrollTop = logWidget.scrollHeight;
        }

        const exportWindow = document.getElementById('log_export_window');
        if (exportWindow && exportWindow.classList.contains('active')) {
            if (window.pywebview) {
                window.pywebview.api.get_logs().then(logs => {
                    const logList = logs.reverse().map(log => ({
                        time_str: `[${log.time_str}]`,
                        level: log.level,
                        action: log.action,
                        source: log.source ? log.source : '-',
                        id: log.id
                    }));
                    renderDataGrid('#log_export_window', logList, cols.log, 'id', true);
                });
            }
        }

        if ((entry.action === 'System' && entry.detail === 'Engine Initialization Complete') || 
            (entry.level === 'WARN' && entry.action === 'init_engine_thread')) {
            const overlay = document.getElementById('loading_overlay');
            const appContainer = document.querySelector('.app-container');
            if (overlay && !overlay.classList.contains('fade-out')) {
                overlay.classList.add('fade-out');
                setTimeout(() => {
                    if (appContainer) appContainer.classList.add('fade-in');
                    if (window.onEngineReady) window.onEngineReady();
                }, 400);
            }
        }
    };

    function formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    document.querySelector('#junk_window .primary-btn')?.addEventListener('click', () => {
        if (!window.pywebview) return;
        const btn = document.querySelector('#junk_window .primary-btn');
        btn.textContent = getMsg("正在初始化中");
        
        const widget = document.querySelector('#junk_window .manage-widget');
        if (widget && widget.gridState) widget.gridState.checkedSet.clear();
        
        window.pywebview.api.scan_system_junk().then(list => {
            currentJunkList = list.map(item => ({
                path: item.path,
                sizeStr: formatSize(item.size),
                size: item.size
            }));
            renderDataGrid('#junk_window', currentJunkList, cols.junk, 'path', true);
            btn.textContent = getMsg("掃描");
        });
    });

    document.querySelector('#repair_window .primary-btn')?.addEventListener('click', () => {
        if (!window.pywebview) return;
        const widget = document.querySelector('#repair_window .manage-widget');
        if (widget && widget.gridState) widget.gridState.checkedSet.clear();
        
        window.pywebview.api.scan_system_repair().then(list => {
            const repairData = list.map(item => ({ display: getMsg(item.display), value: item.value }));
            renderDataGrid('#repair_window', repairData, cols.repair, 'value', true);
        });
    });

    document.querySelector('#junk_window .danger-btn')?.addEventListener('click', () => {
        if (!window.pywebview) return;
        const checkedPaths = getCheckedValues('#junk_window');
        if (checkedPaths.length === 0) return;
        
        window.pywebview.api.clean_system_junk(checkedPaths).then(deletedSize => {
            const msg = getMsg("已清理 ");
            window.pywebview.api.show_alert(getMsg("提示"), `${msg}${formatSize(deletedSize)}`, "info");
            currentJunkList = currentJunkList.filter(item => !checkedPaths.includes(item.path));
            renderDataGrid('#junk_window', currentJunkList, cols.junk, 'path', true);
        });
    });

    function refreshConfigLists() {
        if (!window.pywebview) return;
        window.pywebview.api.get_config().then(cfg => {
            renderDataGrid('#whitelist_window', (cfg.white_list || []).map(i => ({path: i.file || i})), cols.pathOnly, 'path');
            renderDataGrid('#quarantine_window', (cfg.quarantine || []).map(i => ({path: i.file || i})), cols.pathOnly, 'path');
            renderDataGrid('#custom_protect_window', (cfg.custom_rule || []).map(i => ({path: i.file || i})), cols.pathOnly, 'path');
            
            const popupRules = (cfg.block_list || []).map(item => ({
                exe: item.exe || '*',
                class: item.class || '*',
                title: item.title || '*',
                value: item.exe || item.title 
            }));
            renderDataGrid('#popup_window', popupRules, cols.popup, 'value');
        });
    }

    document.querySelector('#whitelist_window .modern-btn:not(.primary-btn)')?.addEventListener('click', () => {
        if (!window.pywebview) return;
        const checked = getCheckedValues('#whitelist_window');
        if (checked.length > 0) window.pywebview.api.remove_list_items('white_list', checked).then(refreshConfigLists);
    });

    document.querySelector('#quarantine_window .modern-btn:not(.primary-btn)')?.addEventListener('click', () => {
        if (!window.pywebview) return;
        const checked = getCheckedValues('#quarantine_window');
        if (checked.length > 0) window.pywebview.api.remove_list_items('quarantine', checked).then(refreshConfigLists);
    });

    document.querySelector('#popup_window .modern-btn:not(.primary-btn)')?.addEventListener('click', () => {
        if (!window.pywebview) return;
        const checked = getCheckedValues('#popup_window');
        if (checked.length > 0) window.pywebview.api.remove_list_items('block_list', checked).then(refreshConfigLists);
    });

    document.querySelector('#custom_protect_window .modern-btn:not(.primary-btn)')?.addEventListener('click', () => {
        if (!window.pywebview) return;
        const checked = getCheckedValues('#custom_protect_window');
        if (checked.length > 0) window.pywebview.api.remove_list_items('custom_rule', checked).then(refreshConfigLists);
    });

    document.querySelector('#whitelist_window .primary-btn')?.addEventListener('click', () => {
        window.pywebview?.api.select_files().then(files => {
            if (files && files.length > 0) window.pywebview.api.manage_named_list('white_list', files, 'add').then(refreshConfigLists);
        });
    });
    
    document.querySelector('#quarantine_window .primary-btn')?.addEventListener('click', () => {
        window.pywebview?.api.select_files().then(files => {
            if (files && files.length > 0) window.pywebview.api.manage_named_list('quarantine', files, 'add').then(refreshConfigLists);
        });
    });

    document.querySelector('#custom_protect_window .primary-btn')?.addEventListener('click', () => {
        window.pywebview?.api.select_files().then(files => {
            if (files && files.length > 0) window.pywebview.api.manage_named_list('custom_rule', files, 'add').then(refreshConfigLists);
        });
    });

    document.querySelector('#repair_window .primary-btn')?.addEventListener('click', () => {
        if (!window.pywebview) return;
        window.pywebview.api.scan_system_repair().then(list => {
            const repairData = list.map(item => ({ display: getMsg(item.display), value: item.value }));
            renderDataGrid('#repair_window', repairData, cols.repair, 'value', true);
        });
    });
    
    document.querySelector('#repair_window .danger-btn')?.addEventListener('click', () => {
        if (!window.pywebview) return;
        const checkedPaths = getCheckedValues('#repair_window');
        if (checkedPaths.length === 0) return;
        window.pywebview.api.execute_system_repair(checkedPaths).then(() => {
            const msg = getMsg("已修復選取項目");
            window.pywebview.api.show_alert(getMsg("提示"), msg, "info");
            renderDataGrid('#repair_window', [], cols.repair, 'value');
        });
    });

    document.getElementById('minimize_button')?.addEventListener('click', () => window.pywebview?.api.minimize());
    document.getElementById('close_button')?.addEventListener('click', () => window.pywebview?.api.hide_window());
    
    const websiteBtn = Array.from(document.querySelectorAll('#about_window .list-item')).find(el => {
        const h2 = el.querySelector('h2');
        return h2 && (h2.dataset.originText === '官方網站' || h2.textContent.includes('官方網站'));
    });
    if (websiteBtn) {
        websiteBtn.querySelector('button').addEventListener('click', () => {
            if (window.pywebview) window.pywebview.api.open_website();
        });
    }

    const updateBtn = Array.from(document.querySelectorAll('#about_window .list-item')).find(el => {
        const h2 = el.querySelector('h2');
        return h2 && (h2.dataset.originText === '檢查更新' || h2.textContent.includes('檢查更新'));
    });
    if (updateBtn) {
        updateBtn.querySelector('button').addEventListener('click', () => {
            if (window.pywebview) {
                window.pywebview.api.check_update().then(res => {
                    if (res.error) {
                        window.pywebview.api.show_alert(getMsg("錯誤"), getMsg("檢查更新失敗"), "error");
                    } else if (res.has_update) {
                        const msg = getMsg("發現新版本");
                        window.pywebview.api.show_confirm(getMsg("提示"), `${msg} ${res.latest}\n(${res.current} -> ${res.latest})`).then(confirmRes => {
                            if (confirmRes) window.pywebview.api.open_url(res.url);
                        });
                    } else {
                        const msg = getMsg("當前已是最新版本");
                        window.pywebview.api.show_alert(getMsg("提示"), `${msg} ${res.current}`, "info");
                    }
                });
            }
        });
    }

    const resetBtn = Array.from(document.querySelectorAll('#setting_window .list-item')).find(el => {
        const h2 = el.querySelector('h2');
        return h2 && (h2.dataset.originText === '重置選項' || h2.textContent.includes('重置選項'));
    });
    if (resetBtn) {
        resetBtn.querySelector('button').addEventListener('click', () => {
            const confirmMsg = getMsg("此選項可以重置所有設定");
            if (window.pywebview) {
                window.pywebview.api.show_confirm(getMsg("提示"), confirmMsg).then(res => {
                    if (res) {
                        window.pywebview.api.reset_config().then(() => {
                            window.pywebview.api.show_alert(getMsg("提示"), getMsg("設定已重置，請重新啟動程式以套用預設值。"), "info");
                        });
                    }
                });
            }
        });
    }

    document.querySelector('#log_export_window .primary-btn')?.addEventListener('click', () => {
        if (window.pywebview) {
            const checkedIds = getCheckedValues('#log_export_window');
            if (checkedIds.length === 0) {
                window.pywebview.api.show_alert(getMsg("提示"), getMsg("請選擇要導出的日誌"), "warning");
                return;
            }
            window.pywebview.api.export_logs(checkedIds).then(res => {
                if (res) window.pywebview.api.show_alert(getMsg("提示"), getMsg("導出成功"), "info");
            });
        }
    });
    
    document.querySelector('#log_export_window .danger-btn')?.addEventListener('click', () => {
        const checkedIds = getCheckedValues('#log_export_window');
        if (checkedIds.length === 0) return;
        
        const confirmMsg = getMsg("確定刪除選取的日誌記錄嗎？");
        if (window.pywebview) {
            window.pywebview.api.show_confirm(getMsg("提示"), confirmMsg).then(res => {
                if (res) {
                    window.pywebview.api.clear_logs(checkedIds).then(() => {
                        window.pywebview.api.get_logs().then(logs => {
                            const logList = logs.reverse().map(log => ({
                                time_str: `[${log.time_str}]`,
                                level: log.level,
                                action: log.action,
                                source: log.source ? log.source : '-',
                                id: log.id
                            }));
                            renderDataGrid('#log_export_window', logList, cols.log, 'id', true);
                        });
                        const successMsg = getMsg("選取的日誌已刪除。");
                        window.pywebview.api.show_alert(getMsg("提示"), successMsg, "info");
                    });
                }
            });
        }
    });

    let currentProcessList = [];
    function updateProcessList(procs) {
        currentProcessList = procs.map(p => ({
            name: p.name,
            pid: p.pid,
            path: p.path && p.path !== "None" ? p.path : getMsg("未知路徑")
        }));
        renderDataGrid('#taskmgr_window', currentProcessList, cols.process, 'pid', false);
    }

    document.querySelector('#taskmgr_window .primary-btn')?.addEventListener('click', () => {
        const cbs = document.querySelectorAll('#taskmgr_window .manage-list-item input[type="checkbox"]:checked');
        if (cbs.length > 0 && window.pywebview) {
            cbs.forEach(cb => {
                const path = cb.dataset.path;
                if (path && path !== "Unknown" && path !== "None") {
                    window.pywebview.api.open_file_location(path);
                }
            });
        }
    });
    
    document.querySelector('#popup_window .primary-btn')?.addEventListener('click', () => {
        if (!window.pywebview) return;
        const btn = document.querySelector('#popup_window .primary-btn');
        const originalText = btn.textContent;
        const waitText = getMsg("請在5秒內點擊目標視窗...");
        
        btn.textContent = waitText;
        btn.disabled = true;
        
        window.pywebview.api.capture_popup_window().then(rule => {
            btn.textContent = originalText;
            btn.disabled = false;
            if (rule) {
                window.pywebview.api.add_popup_rule(rule).then(success => {
                    if (success) refreshConfigLists();
                });
            }
        });
    });

    document.querySelector('#taskmgr_window .danger-btn')?.addEventListener('click', () => {
        const cbs = document.querySelectorAll('#taskmgr_window .manage-list-item input[type="checkbox"]:checked');
        const confirmMsg = getMsg("確定要結束選取的進程嗎？");
        if (cbs.length > 0 && window.pywebview) {
            window.pywebview.api.show_confirm(getMsg("提示"), confirmMsg).then(res => {
                if (res) {
                    const promises = Array.from(cbs).map(cb => window.pywebview.api.kill_process(parseInt(cb.value)));
                    Promise.all(promises).then(() => {
                        window.pywebview.api.get_process_list().then(updateProcessList);
                    });
                }
            });
        }
    });
    
    const contextMenu = document.createElement('div');
    contextMenu.className = 'custom-context-menu';
    contextMenu.innerHTML = `
        <div class="custom-context-menu-item" id="ctx_open_location">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg>
            <span data-i18n>打開檔案所在位置</span>
        </div>
    `;
    document.body.appendChild(contextMenu);

    const ctxSpan = contextMenu.querySelector('span[data-i18n]');
    ctxSpan.dataset.originText = ctxSpan.textContent.trim();

    let contextMenuTarget = null;

    document.addEventListener('contextmenu', (e) => {
        const listItem = e.target.closest('.manage-list-item');
        if (listItem) {
            const cb = listItem.querySelector('input[type="checkbox"]');
            const path = cb ? cb.dataset.path : null;
            
            if (path && path !== "Unknown" && path !== "None") {
                e.preventDefault();
                contextMenuTarget = path;
                
                ctxSpan.textContent = getMsg(ctxSpan.dataset.originText);
                
                contextMenu.style.left = `${e.clientX}px`;
                contextMenu.style.top = `${e.clientY}px`;
                contextMenu.classList.add('show');
                
                const rect = contextMenu.getBoundingClientRect();
                if (rect.right > window.innerWidth) {
                    contextMenu.style.left = `${window.innerWidth - rect.width - 5}px`;
                }
                if (rect.bottom > window.innerHeight) {
                    contextMenu.style.top = `${window.innerHeight - rect.height - 5}px`;
                }
                return;
            }
        }
        contextMenu.classList.remove('show');
    });

    document.addEventListener('click', (e) => {
        if (!e.target.closest('.custom-context-menu')) {
            contextMenu.classList.remove('show');
        }
    });

    document.addEventListener('scroll', () => {
        contextMenu.classList.remove('show');
    }, true);

    document.getElementById('ctx_open_location').addEventListener('click', () => {
        if (window.pywebview && contextMenuTarget) {
            window.pywebview.api.open_file_location(contextMenuTarget);
        }
        contextMenu.classList.remove('show');
    });
});