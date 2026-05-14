['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    document.addEventListener(eventName, e => {
        e.preventDefault();
    });
});

document.addEventListener('DOMContentLoaded', () => {
    const { dict, langMap } = window.AppI18n;

    const appState = {
        lang: "english_switch",
        scanning: false,
        firstLaunch: false,
        taskmgrTimer: null,
        taskmgrActive: false,
        virusMap: new Map(),
        virusResults: [],
        junkList: []
    };

    const reverseI18nMap = Object.entries(dict["traditional_switch"]).reduce((acc, [key, val]) => {
        acc[val] = key;
        return acc;
    }, {});

    const initI18nKeys = () => {
        document.querySelectorAll("[data-i18n]").forEach(el => {
            let key = el.getAttribute('data-i18n');
            if (!key) {
                const text = el.textContent.trim();
                key = reverseI18nMap[text] || text;
                el.setAttribute('data-i18n', key);
            }
            el.dataset.originText = el.textContent.trim();
        });
        document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
            let key = el.getAttribute('data-i18n-placeholder');
            if (reverseI18nMap[key]) {
                el.setAttribute('data-i18n-placeholder', reverseI18nMap[key]);
            }
            el.dataset.originPlaceholder = el.getAttribute('placeholder');
        });
        document.querySelectorAll("option[data-i18n]").forEach(el => {
            let key = el.getAttribute('data-i18n');
            if (!key) {
                const text = el.textContent.trim();
                key = reverseI18nMap[text] || text;
                el.setAttribute('data-i18n', key);
            }
        });
    };

    document.addEventListener('click', () => {
        document.querySelectorAll('.custom-select-wrapper').forEach(w => w.classList.remove('open'));
    });

    const getMsg = (key) => (dict[appState.lang] || dict["english_switch"])[key] || key;

    const formatMsg = (key, ...args) => {
        let msg = getMsg(key);
        args.forEach((arg, i) => msg = msg.split(`{${i}}`).join(arg));
        return msg;
    };

    const escapeHtml = (unsafe) => {
        if (typeof unsafe !== 'string') return unsafe;
        return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
    };

    const themes = {
        "white_switch": { "--bg-window": "245, 245, 247", "--bg-nav": "255, 255, 255", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(0,0,0,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--border-color":"210, 210, 215", "--accent-color":"0, 122, 255", "--accent-alpha":"rgba(0, 122, 255, 0.1)", "--accent-shadow":"rgba(0, 122, 255, 0.2)", "--accent-hover":"rgba(0, 122, 255, 0.3)" },
        "black_switch": { "--bg-window": "0, 0, 0", "--bg-nav": "28, 28, 30", "--bg-panel": "28, 28, 30", "--bg-hover": "rgba(255,255,255,0.1)", "--text-primary": "245, 245, 247", "--text-secondary": "134, 134, 139", "--border-color":"44, 44, 46", "--accent-color":"10, 132, 255", "--accent-alpha":"rgba(10, 132, 255, 0.1)", "--accent-shadow":"rgba(10, 132, 255, 0.2)", "--accent-hover":"rgba(10, 132, 255, 0.3)" },
        "red_switch": { "--bg-window": "253, 246, 246", "--bg-nav": "255, 240, 240", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(255,59,48,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--border-color":"250, 220, 220", "--accent-color":"255, 59, 48", "--accent-alpha":"rgba(255, 59, 48, 0.1)", "--accent-shadow":"rgba(255, 59, 48, 0.2)", "--accent-hover":"rgba(255, 59, 48, 0.3)" },
        "yellow_switch": { "--bg-window": "254, 251, 243", "--bg-nav": "255, 248, 230", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(255,149,0,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--border-color":"250, 240, 215", "--accent-color":"255, 149, 0", "--accent-alpha":"rgba(255, 149, 0, 0.1)", "--accent-shadow":"rgba(255, 149, 0, 0.2)", "--accent-hover":"rgba(255, 149, 0, 0.3)" },
        "green_switch": { "--bg-window": "246, 253, 248", "--bg-nav": "235, 250, 240", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(52,199,89,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--border-color":"220, 240, 225", "--accent-color":"52, 199, 89", "--accent-alpha":"rgba(52, 199, 89, 0.1)", "--accent-shadow":"rgba(52, 199, 89, 0.2)", "--accent-hover":"rgba(52, 199, 89, 0.3)" },
        "blue_switch": { "--bg-window": "246, 249, 253", "--bg-nav": "235, 244, 255", "--bg-panel": "255, 255, 255", "--bg-hover": "rgba(0,122,255,0.05)", "--text-primary": "29, 29, 31", "--text-secondary": "134, 134, 139", "--border-color":"220, 230, 250", "--accent-color":"0, 122, 255", "--accent-alpha":"rgba(0, 122, 255, 0.1)", "--accent-shadow":"rgba(0, 122, 255, 0.2)", "--accent-hover":"rgba(0, 122, 255, 0.3)" }
    };

    const cols = {
        log: [{key: 'time_str', label: 'col_date', flex: 1.5}, {key: 'level', label: 'col_type', flex: 0.8}, {key: 'action', label: 'col_func', flex: 1.2, isI18n: true}, {key: 'source', label: 'col_path', flex: 3}],
        process: [{key: 'name', label: 'col_name', flex: 1.5}, {key: 'pid', label: 'col_pid', flex: 0.5}, {key: 'path', label: 'col_path', flex: 3}],
        virus: [{key: 'label', label: 'col_type', flex: 1, isI18n: true}, {key: 'path', label: 'col_path', flex: 3}],
        pathOnly: [{key: 'path', label: 'col_path', flex: 1}],
        junk: [{key: 'path', label: 'col_path', flex: 3}, {key: 'sizeStr', label: 'col_size', flex: 1}],
        popup: [{key: 'exe', label: 'col_prog', flex: 1}, {key: 'class', label: 'col_class', flex: 1}, {key: 'title', label: 'col_title', flex: 2}],
        repair: [{key: 'display', label: 'col_repair', flex: 1, isI18n: true}]
    };

    const buildCustomSelectElement = (select) => {
        select.style.display = 'none';
        const wrapper = document.createElement('div');
        wrapper.className = 'custom-select-wrapper';
        
        const selectedOpt = select.options[select.selectedIndex];
        const triggerKey = selectedOpt ? selectedOpt.getAttribute('data-i18n') : '';
        const triggerTextContent = selectedOpt ? getMsg(triggerKey || selectedOpt.textContent) : '';

        const triggerHTML = `
            <div class="custom-select-trigger">
                <span class="custom-select-text" ${triggerKey ? `data-i18n="${triggerKey}"` : ''}>${triggerTextContent}</span>
                <div class="custom-select-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg></div>
            </div>`;
        wrapper.innerHTML = triggerHTML;
        
        const optionsContainer = document.createElement('ul');
        optionsContainer.className = 'custom-select-options';

        const phantom = document.createElement('div');
        phantom.className = 'custom-select-phantom';
        phantom.setAttribute('aria-hidden', 'true');
        
        Array.from(select.options).forEach(option => {
            if (option.disabled) return;
            const optKey = option.getAttribute('data-i18n');
            const optText = optKey ? getMsg(optKey) : option.textContent;
            
            const li = document.createElement('li');
            li.className = `custom-select-option ${option.selected ? 'selected' : ''}`;
            li.textContent = optText;
            li.dataset.value = option.value;
            if (optKey) li.setAttribute('data-i18n', optKey);
            
            li.addEventListener('click', (e) => {
                e.stopPropagation();
                select.value = option.value;
                const triggerText = wrapper.querySelector('.custom-select-text');
                triggerText.textContent = li.textContent;
                if (optKey) triggerText.setAttribute('data-i18n', optKey);
                
                wrapper.classList.remove('open');
                optionsContainer.querySelectorAll('.custom-select-option').forEach(el => el.classList.remove('selected'));
                li.classList.add('selected');
                select.dispatchEvent(new Event('change'));
            });
            optionsContainer.appendChild(li);

            const phantomSpan = document.createElement('span');
            phantomSpan.textContent = optText;
            if (optKey) phantomSpan.setAttribute('data-i18n', optKey);
            phantom.appendChild(phantomSpan);
        });
        
        wrapper.appendChild(phantom);
        wrapper.appendChild(optionsContainer);
        select.parentNode.insertBefore(wrapper, select.nextSibling);
        
        const trigger = wrapper.querySelector('.custom-select-trigger');
        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = wrapper.classList.contains('open');
            document.querySelectorAll('.custom-select-wrapper').forEach(w => w.classList.remove('open'));
            if (!isOpen) wrapper.classList.add('open');
        });
    };

    const updateCustomSelectUI = (selectId, val) => {
        const select = document.getElementById(selectId);
        if (!select) return;
        select.value = val;
        const wrapper = select.nextElementSibling;
        if (wrapper && wrapper.classList.contains('custom-select-wrapper')) {
            const triggerText = wrapper.querySelector('.custom-select-text');
            const selectedOpt = select.options[select.selectedIndex];
            if (selectedOpt) {
                const optKey = selectedOpt.getAttribute('data-i18n');
                triggerText.textContent = optKey ? getMsg(optKey) : selectedOpt.textContent;
                if (optKey) triggerText.setAttribute('data-i18n', optKey);
            }
            wrapper.querySelectorAll('.custom-select-option').forEach(el => {
                el.classList.toggle('selected', el.dataset.value === val);
            });
        }
    };

    const translateText = (lang) => {
        appState.lang = lang;
        document.querySelectorAll("[data-i18n]").forEach(el => {
            const key = el.getAttribute('data-i18n');
            if (key) el.textContent = getMsg(key);
        });
        document.querySelectorAll("[data-i18n-placeholder]").forEach(el => {
            const key = el.getAttribute('data-i18n-placeholder');
            if (key) el.setAttribute('placeholder', getMsg(key));
        });
        document.querySelectorAll('.manage-widget, .virus-widget').forEach(widget => {
            if (widget.buildHeader) widget.buildHeader();
            if (widget.renderData) widget.renderData();
        });
        document.documentElement.lang = langMap[lang] || "en";

        const progressText = document.getElementById('progress_text');
        if (progressText && progressText.dataset.dynamicMsg) {
            try {
                const msgs = JSON.parse(progressText.dataset.dynamicMsg);
                if (msgs[lang]) progressText.textContent = msgs[lang];
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

    const renderDataGrid = (containerSelector, dataList, columns, valKey, defaultChecked = false) => {
        const widget = document.querySelector(`${containerSelector} .manage-widget`) || document.querySelector(`${containerSelector} .virus-widget`);
        const listUl = document.querySelector(`${containerSelector} .manage-list`) || document.querySelector(`${containerSelector} .virus-list`);
        const searchInput = document.querySelector(`${containerSelector} .search-box input`);
        if (!widget || !listUl) return;

        const isInit = !widget.gridState;
        if (isInit) {
            const containerWidth = widget.clientWidth || 800;
            const availableWidth = Math.max(containerWidth - 60 - (columns.length * 16), 400); 
            const totalFlex = columns.reduce((sum, c) => sum + (c.flex || 1), 0);
            
            widget.gridState = { 
                sortKey: columns[0]?.key || '', sortAsc: true, filterText: "",
                colWidths: columns.map(c => Math.max(((c.flex || 1) / totalFlex) * availableWidth, 60)),
                checkedSet: new Set()
            };
            
            widget.gridState.colWidths.forEach((w, idx) => widget.style.setProperty(`--col-${idx}`, `${w}px`));
            const header = document.createElement('div');
            header.className = 'manage-list-header';
            widget.insertBefore(header, widget.firstChild);

            widget.buildHeader = () => {
                const headerColsHtml = columns.map((col, idx) => `
                    <div class="col-header" data-key="${col.key}" data-idx="${idx}" style="width: var(--col-${idx}); flex: 0 0 auto;">
                        <span class="header-text" data-i18n="${col.label}">${getMsg(col.label)}</span>
                        <span class="sort-icon">${widget.gridState.sortKey === col.key ? (widget.gridState.sortAsc ? '▲' : '▼') : ''}</span>
                        <div class="col-resizer"></div>
                    </div>`).join('');

                header.innerHTML = `<input type="checkbox" class="select-all-cb" title="${getMsg('btn_select_all')}"><div class="header-cols-container">${headerColsHtml}</div>`;

                header.querySelectorAll('.col-header').forEach(el => {
                    el.addEventListener('click', () => {
                        const key = el.dataset.key;
                        widget.gridState.sortAsc = widget.gridState.sortKey === key ? !widget.gridState.sortAsc : true;
                        widget.gridState.sortKey = key;
                        widget.buildHeader(); 
                        widget.renderData(widget.gridState.filterText, false); 
                    });
                });

                header.querySelectorAll('.col-resizer').forEach(resizer => {
                    resizer.addEventListener('mousedown', (e) => {
                        e.stopPropagation();
                        const idx = parseInt(resizer.parentElement.dataset.idx);
                        const startX = e.clientX;
                        const startWidth = widget.gridState.colWidths[idx];

                        const onMouseMove = (me) => {
                            const newWidth = Math.max(startWidth + (me.clientX - startX), 40);
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
                        listUl.querySelectorAll('.manage-list-item input[type="checkbox"]').forEach(cb => cb.checked = isChecked);
                        (widget.gridState.lastDisplayData || []).forEach(item => {
                            const valStr = String(item[valKey]);
                            isChecked ? widget.gridState.checkedSet.add(valStr) : widget.gridState.checkedSet.delete(valStr);
                            if (containerSelector === '#scan_window') appState.virusMap.set(valStr, isChecked);
                        });
                        if (containerSelector === '#scan_window') checkVirusListEmpty();
                    });
                }
            };
            widget.buildHeader();

            listUl.addEventListener('click', (e) => {
                const li = e.target.closest('.manage-list-item');
                if (!li) return;
                const cb = li.querySelector('input[type="checkbox"]');
                if (e.target.tagName !== 'INPUT') cb.checked = !cb.checked;
                
                cb.checked ? widget.gridState.checkedSet.add(cb.value) : widget.gridState.checkedSet.delete(cb.value);
                if (containerSelector === '#scan_window') {
                    appState.virusMap.set(cb.value, cb.checked);
                    checkVirusListEmpty();
                }
                if (widget.updateSelectAllState) widget.updateSelectAllState();
            });

            if (searchInput) searchInput.addEventListener('input', (e) => widget.renderData(e.target.value, false));
        }

        const state = widget.gridState;
        widget.renderData = (filterText = state.filterText, resetDataCheck = false) => {
            state.filterText = filterText;
            if (resetDataCheck) {
                state.checkedSet.clear();
                if (defaultChecked) dataList.forEach(item => state.checkedSet.add(String(item[valKey])));
            } else {
                const validKeys = new Set(dataList.map(item => String(item[valKey])));
                for (const val of state.checkedSet) if (!validKeys.has(val)) state.checkedSet.delete(val);
                if (state.checkedSet.size === 0 && defaultChecked && dataList.length > 0) {
                    if (!listUl.querySelector('input[type="checkbox"]:checked')) {
                        dataList.forEach(item => state.checkedSet.add(String(item[valKey])));
                    }
                }
            }

            const header = widget.querySelector('.manage-list-header');
            const selectAllCb = header ? header.querySelector('.select-all-cb') : null;
            if (selectAllCb) selectAllCb.disabled = dataList.length === 0;

            const ft = filterText.toLowerCase();
            let displayData = dataList.filter(item => !filterText || columns.some(col => String(item[col.key] || '').toLowerCase().includes(ft)));

            displayData.sort((a, b) => {
                const valA = a[state.sortKey] ?? '', valB = b[state.sortKey] ?? '';
                if (state.sortKey === 'sizeStr' && 'size' in a && 'size' in b) return state.sortAsc ? a.size - b.size : b.size - a.size;
                const numA = parseFloat(valA), numB = parseFloat(valB);
                if (!isNaN(numA) && !isNaN(numB) && String(valA).trim() !== '' && String(valB).trim() !== '') return state.sortAsc ? numA - numB : numB - numA;
                return state.sortAsc ? String(valA).localeCompare(String(valB)) : String(valB).localeCompare(String(valA));
            });

            widget.gridState.lastDisplayData = displayData;
            widget.updateSelectAllState = () => {
                if (!selectAllCb) return;
                const cData = widget.gridState.lastDisplayData || [];
                if (cData.length === 0) { selectAllCb.checked = false; selectAllCb.indeterminate = false; return; }
                const checkedCount = cData.filter(item => containerSelector === '#scan_window' ? appState.virusMap.get(String(item[valKey])) : widget.gridState.checkedSet.has(String(item[valKey]))).length;
                selectAllCb.checked = (checkedCount > 0 && checkedCount === cData.length);
                selectAllCb.indeterminate = (checkedCount > 0 && checkedCount < cData.length);
            };

            const MAX_ITEMS = 2000;
            const limitData = displayData.slice(0, MAX_ITEMS);
            
            let htmlContent = limitData.map(item => {
                const itemValStr = String(item[valKey]);
                let isChecked = containerSelector === '#scan_window' ? (appState.virusMap.get(itemValStr) ?? true) : state.checkedSet.has(itemValStr);
                if (containerSelector === '#scan_window') appState.virusMap.set(itemValStr, isChecked);
                
                const rowColsHtml = columns.map((col, idx) => {
                    const rawVal = String(item[col.key] || '');
                    let valStr = col.isI18n ? getMsg(rawVal) : rawVal;
                    if (rawVal === '未知路徑' || rawVal === 'path_unknown') valStr = getMsg('path_unknown');
                    return `<div class="row-col" style="width: var(--col-${idx}); flex: 0 0 auto;" title="${escapeHtml(valStr)}">${escapeHtml(valStr)}</div>`;
                }).join('');

                return `<li class="manage-list-item"><input type="checkbox" value="${escapeHtml(itemValStr)}" ${isChecked ? 'checked' : ''} data-path="${escapeHtml(item.path || '')}"><div class="manage-list-item-content">${rowColsHtml}</div></li>`;
            }).join('');

            if (displayData.length > MAX_ITEMS) {
                htmlContent += `<li class="manage-list-item" style="pointer-events: none; justify-content: center;"><div style="color: var(--text-secondary); padding: 10px;">${escapeHtml(formatMsg("msg_too_many", MAX_ITEMS))}</div></li>`;
            }

            const scrollContainer = listUl.parentElement;
            const scrollTop = scrollContainer ? scrollContainer.scrollTop : 0;
            listUl.innerHTML = htmlContent;
            if (scrollContainer) scrollContainer.scrollTop = scrollTop;
            widget.updateSelectAllState();
        };
        widget.renderData(state.filterText, isInit);
    };

    const getCheckedValues = (selector) => Array.from(document.querySelectorAll(`${selector} .manage-list-item input[type="checkbox"]:checked`)).map(cb => cb.value);
    const formatSize = (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'], i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    const rebuildCustomSelect = (selectId) => {
        const select = document.getElementById(selectId);
        if (!select) return;
        let sibling = select.nextElementSibling;
        while (sibling && sibling.classList.contains('custom-select-wrapper')) {
            const toRemove = sibling;
            sibling = sibling.nextElementSibling;
            toRemove.remove();
        }
        buildCustomSelectElement(select);
    };

    const changeScanSelectMode = (mode) => {
        const select = document.getElementById('scan_method_select');
        if (!select) return;
        select.innerHTML = `<option value="none" selected disabled data-i18n="btn_select">${getMsg('btn_select')}</option>`;
        if (mode === 'scan') {
            select.innerHTML += `
                <option value="smart" data-i18n="scan_smart">${getMsg('scan_smart')}</option>
                <option value="file" data-i18n="scan_file">${getMsg('scan_file')}</option>
                <option value="path" data-i18n="scan_path">${getMsg('scan_path')}</option>
                <option value="full" data-i18n="scan_full">${getMsg('scan_full')}</option>`;
        } else if (mode === 'action') {
            select.innerHTML += `
                <option value="delete" data-i18n="act_del">${getMsg('act_del')}</option>
                <option value="ignore" data-i18n="act_ignore">${getMsg('act_ignore')}</option>
                <option value="quarantine" data-i18n="act_quarantine">${getMsg('act_quarantine')}</option>
                <option value="whitelist" data-i18n="act_white">${getMsg('act_white')}</option>`;
        }
        rebuildCustomSelect('scan_method_select');
    };

    const checkVirusListEmpty = () => {
    updateCustomSelectUI('scan_method_select', 'none');
    if (appState.virusResults.length === 0) {
        appState.virusMap.clear();
        changeScanSelectMode('scan');
        const title = document.querySelector('#scan_window .section-title');
        const text = document.getElementById('progress_text');
        if (title) { 
            title.setAttribute('data-i18n', 'scan_virus'); 
            title.textContent = getMsg('scan_virus'); 
        }
        if (text) {
            text.setAttribute('data-i18n', 'scan_virus_desc');
            text.removeAttribute('data-dynamic-msg');
            text.textContent = getMsg('scan_virus_desc');
        }
    }
};

    const triggerScan = (method) => {
        if (!window.pywebview) return;
        appState.scanning = true;
        appState.virusMap.clear();
        appState.virusResults = [];
        renderDataGrid('#scan_window', appState.virusResults, cols.virus, 'path', true);
        changeScanSelectMode('scan');
        document.getElementById('scan_method_select').classList.add('hidden');
        const stopBtn = document.getElementById('stop_btn');
        stopBtn.classList.remove('hidden');
        stopBtn.disabled = false;
        
        const title = document.querySelector('#scan_window .section-title');
        const text = document.getElementById('progress_text');
        if (title) { title.setAttribute('data-i18n', 'status_scanning'); title.textContent = getMsg('status_scanning'); }
        if (text) { text.setAttribute('data-i18n', 'msg_init'); text.removeAttribute('data-dynamic-msg'); text.textContent = getMsg('msg_init'); }
        window.pywebview.api.trigger_scan(method);
    };

    const handleVirusActions = (action) => {
        if (!window.pywebview) return;
        const paths = Array.from(appState.virusMap.entries()).filter(([_, checked]) => checked).map(([p]) => p);
        if (paths.length === 0) return updateCustomSelectUI('scan_method_select', 'none');

        const wrapper = document.getElementById('scan_method_select').nextElementSibling;
        if (wrapper) wrapper.style.pointerEvents = 'none';

        const finalize = () => {
            if (wrapper) wrapper.style.pointerEvents = '';
            checkVirusListEmpty();
        };

        const removeItems = (removedPaths) => {
            const removedSet = new Set(removedPaths);
            removedPaths.forEach(p => appState.virusMap.delete(p));
            appState.virusResults = appState.virusResults.filter(r => !removedSet.has(r.path));
            renderDataGrid('#scan_window', appState.virusResults, cols.virus, 'path', false);
        };

        if (action === 'delete') {
            window.pywebview.api.solve_scan(paths).then((deleted) => { removeItems(deleted); finalize(); });
        } else if (action === 'ignore') {
            window.pywebview.api.remove_virus_result(paths).then(() => { removeItems(paths); finalize(); });
        } else if (action === 'quarantine' || action === 'whitelist') {
            const listKey = action === 'quarantine' ? 'quarantine' : 'white_list';
            window.pywebview.api.manage_named_list(listKey, paths, 'add').then(() => {
                window.pywebview.api.remove_virus_result(paths).then(() => { removeItems(paths); finalize(); });
            });
        }
    };

    const fetchProcs = () => {
        if (!appState.taskmgrActive || !window.pywebview) return;
        const widget = document.querySelector('#taskmgr_window .manage-widget');
        const blockFetch = widget && (widget.gridState?.checkedSet.size > 0 || widget.matches(':hover')) || document.querySelector('.custom-context-menu.show') || document.body.classList.contains('resizing-active');
        
        if (!blockFetch) {
            window.pywebview.api.get_process_list().then(procs => {
                const mapped = procs.map(p => ({ name: p.name, pid: p.pid, path: (p.path && p.path !== "None" && p.path !== "Unknown") ? p.path : "path_unknown" }));
                renderDataGrid('#taskmgr_window', mapped, cols.process, 'pid', false);
                if (appState.taskmgrActive) appState.taskmgrTimer = setTimeout(fetchProcs, 2000);
            }).catch(() => { if (appState.taskmgrActive) appState.taskmgrTimer = setTimeout(fetchProcs, 2000); });
        } else {
            if (appState.taskmgrActive) appState.taskmgrTimer = setTimeout(fetchProcs, 2000);
        }
    };

    const refreshConfigLists = () => {
        if (!window.pywebview) return;
        window.pywebview.api.get_config().then(cfg => {
            renderDataGrid('#whitelist_window', (cfg.white_list || []).map(i => ({path: i.file || i})), cols.pathOnly, 'path');
            renderDataGrid('#quarantine_window', (cfg.quarantine || []).map(i => ({path: i.file || i})), cols.pathOnly, 'path');
            renderDataGrid('#custom_protect_window', (cfg.custom_rule || []).map(i => ({path: i.file || i})), cols.pathOnly, 'path');
            const popupRules = (cfg.block_list || []).map(item => ({ exe: item.exe || '*', class: item.class || '*', title: item.title || '*', value: item.exe || item.title }));
            renderDataGrid('#popup_window', popupRules, cols.popup, 'value');
        });
    };

    const switchPage = (targetId) => {
        const oldActive = document.querySelector('.page.active');
        if (oldActive && oldActive.id !== targetId) {
            if (oldActive.id === 'junk_window') {
                appState.junkList = [];
                renderDataGrid('#junk_window', [], cols.junk, 'path', true);
                const input = document.querySelector('#junk_window .search-box input');
                if (input) input.value = '';
            } else if (oldActive.id === 'repair_window') {
                renderDataGrid('#repair_window', [], cols.repair, 'value', true);
            }
        }

        document.querySelectorAll('.page, .nav-btn').forEach(el => el.classList.remove('active'));
        document.getElementById(targetId)?.classList.add('active');
        document.querySelector(`aside .nav-btn[data-target="${targetId}"]`)?.classList.add('active');
        
        appState.taskmgrActive = targetId === 'taskmgr_window';
        if (appState.taskmgrActive) fetchProcs();
        else if (appState.taskmgrTimer) { clearTimeout(appState.taskmgrTimer); appState.taskmgrTimer = null; }

        if (['whitelist_window', 'quarantine_window', 'popup_window', 'custom_protect_window'].includes(targetId)) refreshConfigLists();

        if (targetId === 'log_export_window' && window.pywebview) {
            window.pywebview.api.get_logs().then(logs => {
                const logList = logs.reverse().map(log => ({ time_str: `[${log.time_str}]`, level: log.level, action: log.action, source: log.source || '-', id: log.id }));
                renderDataGrid('#log_export_window', logList, cols.log, 'id', true);
            });
        }
    };

    window.addVirusResult = (label, path) => {
        if (!appState.virusMap.has(path)) {
            appState.virusResults.push({ label, path });
            appState.virusMap.set(path, true);
            const widget = document.querySelector('#scan_window .virus-widget');
            if (widget && widget.renderData) {
                if (window.virusRenderTimeout) clearTimeout(window.virusRenderTimeout);
                window.virusRenderTimeout = setTimeout(() => widget.renderData(widget.gridState.filterText, false), 50);
            }
        }
    };

    window.updateScanProgress = (path) => {
        const title = document.querySelector('#scan_window .section-title');
        const text = document.getElementById('progress_text');
        if (title) { title.setAttribute('data-i18n', 'status_scanning'); title.textContent = getMsg('status_scanning'); }
        if (text) { text.removeAttribute('data-i18n'); text.removeAttribute('data-dynamic-msg'); text.textContent = path; }
    };

    window.updateDeleteProgress = (path) => {
        const title = document.querySelector('#scan_window .section-title');
        const text = document.getElementById('progress_text');
        if (title) { title.setAttribute('data-i18n', 'status_deleting'); title.textContent = getMsg('status_deleting'); }
        if (text) { text.removeAttribute('data-i18n'); text.removeAttribute('data-dynamic-msg'); text.textContent = path; }
    };

    window.finishScan = (msgData, count) => {
        appState.scanning = false;
        const title = document.querySelector('#scan_window .section-title');
        const text = document.getElementById('progress_text');
        if (title) { title.setAttribute('data-i18n', 'scan_virus'); title.textContent = getMsg('scan_virus'); }
        if (text) {
            if (typeof msgData === 'object' && msgData !== null) {
                text.removeAttribute('data-i18n');
                text.dataset.dynamicMsg = JSON.stringify(msgData);
                text.textContent = msgData[appState.lang] || msgData["english_switch"];
            } else {
                text.removeAttribute('data-dynamic-msg');
                text.setAttribute('data-i18n', msgData);
                text.textContent = getMsg(msgData);
            }
        }
        document.getElementById('stop_btn')?.classList.add('hidden');
        document.getElementById('scan_method_select')?.classList.remove('hidden');
        changeScanSelectMode(count > 0 ? 'action' : 'scan');
        updateCustomSelectUI('scan_method_select', 'none');
    };

    window.updateLogs = (entry) => {
        const logWidget = document.querySelector('.log-text');
        if (logWidget) {
            let parts = [`[${entry.time_str}]`, entry.level, getMsg(entry.action || '')];
            if (entry.source) parts.push(`Src: ${entry.source}`);
            if (entry.target) parts.push(`Tgt: ${entry.target}`);
            if (entry.code) parts.push(`Code: ${entry.code}`);
            if (entry.pid) parts.push(`PID: ${entry.pid}`);
            if (entry.hash) parts.push(`Hash: ${entry.hash}`);
            if (entry.detail) parts.push(`Detail: ${entry.detail}`);
            if (entry.operate !== null) parts.push(`Op: ${entry.operate}`);
            parts.push(`Success: ${entry.success}`);
            let val = logWidget.value + parts.join(' | ') + '\n';
            if (val.length > 20000) val = val.substring(val.indexOf('\n', val.length - 15000) + 1);
            logWidget.value = val;
            logWidget.scrollTop = logWidget.scrollHeight;
        }

        if (document.getElementById('log_export_window')?.classList.contains('active') && window.pywebview) {
            window.pywebview.api.get_logs().then(logs => {
                const logList = logs.reverse().map(log => ({ time_str: `[${log.time_str}]`, level: log.level, action: log.action, source: log.source || '-', id: log.id }));
                renderDataGrid('#log_export_window', logList, cols.log, 'id', true);
            });
        }

        if ((entry.action === 'System' && entry.detail === 'Engine Initialization Complete') || (entry.level === 'WARN' && entry.action === 'init_engine_thread')) {
            const overlay = document.getElementById('loading_overlay');
            if (overlay && !overlay.classList.contains('fade-out')) {
                overlay.classList.add('fade-out');
                setTimeout(() => {
                    document.querySelector('.app-container')?.classList.add('fade-in');
                    if (window.onEngineReady) window.onEngineReady();
                }, 400);
            }
        }
    };

    window.triggerContextScan = (targets) => {
        if (appState.scanning) return;
        switchPage('scan_window');
        if (window.pywebview) {
            appState.scanning = true;
            appState.virusMap.clear();
            appState.virusResults = [];
            renderDataGrid('#scan_window', appState.virusResults, cols.virus, 'path', true);
            document.getElementById('scan_method_select')?.classList.add('hidden');
            const stopBtn = document.getElementById('stop_btn');
            if (stopBtn) { stopBtn.classList.remove('hidden'); stopBtn.disabled = false; }
            changeScanSelectMode('scan');
            
            const title = document.querySelector('#scan_window .section-title');
            const text = document.getElementById('progress_text');
            if (title) { title.setAttribute('data-i18n', 'status_scanning'); title.textContent = getMsg('status_scanning'); }
            if (text) { text.setAttribute('data-i18n', 'msg_init'); text.removeAttribute('data-dynamic-msg'); text.textContent = getMsg('msg_init'); }
            
            const paths = Array.isArray(targets) ? targets : [targets];
            window.pywebview.api.start_scan(paths);
        }
    };

    window.revertSwitch = () => {}; 

    document.querySelectorAll('[data-target]').forEach(btn => btn.addEventListener('click', (e) => switchPage(e.currentTarget.getAttribute('data-target'))));
    document.getElementById('quick_scan_btn')?.addEventListener('click', () => { if (!appState.scanning) { switchPage('scan_window'); triggerScan('smart'); }});
    document.getElementById('stop_btn')?.addEventListener('click', (e) => { if (window.pywebview) window.pywebview.api.stop_scan(); e.target.disabled = true; });
    document.getElementById('theme_select')?.addEventListener('change', (e) => { applyTheme(e.target.value); window.pywebview?.api.update_config('theme', e.target.value); });
    document.getElementById('lang_select')?.addEventListener('change', (e) => { translateText(e.target.value); window.pywebview?.api.update_config('language', e.target.value); });
    
    document.getElementById('scan_method_select')?.addEventListener('change', (e) => {
        const val = e.target.value;
        if (val === 'none' || appState.scanning) return;
        if (['smart', 'file', 'path', 'full'].includes(val)) triggerScan(val);
        else if (['delete', 'ignore', 'quarantine', 'whitelist'].includes(val)) handleVirusActions(val);
    });

    document.querySelectorAll('.toggle-switch input').forEach((toggle, index) => {
        toggle.addEventListener('change', async (e) => {
            const switchMap = ["process_switch", "document_switch", "system_switch", "driver_switch", "network_switch", "sensitive_switch", "extension_switch", "cloud_switch", "context_switch"];
            const key = switchMap[index];
            if (window.pywebview && key) {
                toggle.disabled = true;
                try {
                    const result = await window.pywebview.api.update_config(key, e.target.checked);
                    if (result !== undefined && result !== null) toggle.checked = result;
                } catch { toggle.checked = !e.target.checked; } 
                finally { toggle.disabled = false; }
            }
        });
    });

    document.querySelector('#junk_window .primary-btn')?.addEventListener('click', (e) => {
        if (!window.pywebview) return;
        e.target.setAttribute('data-i18n', 'msg_init'); e.target.textContent = getMsg('msg_init');
        const widget = document.querySelector('#junk_window .manage-widget');
        if (widget?.gridState) widget.gridState.checkedSet.clear();
        
        window.pywebview.api.scan_system_junk().then(list => {
            appState.junkList = list.map(item => ({ path: item.path, sizeStr: formatSize(item.size), size: item.size }));
            renderDataGrid('#junk_window', appState.junkList, cols.junk, 'path', true);
            e.target.setAttribute('data-i18n', 'btn_scan'); e.target.textContent = getMsg('btn_scan');
        });
    });

    document.querySelector('#junk_window .danger-btn')?.addEventListener('click', () => {
        const checked = getCheckedValues('#junk_window');
        if (checked.length === 0 || !window.pywebview) return;
        window.pywebview.api.clean_system_junk(checked).then(size => {
            window.pywebview.api.show_alert(getMsg("title_prompt"), `${getMsg("msg_cleaned")}${formatSize(size)}`, "info");
            appState.junkList = appState.junkList.filter(item => !checked.includes(item.path));
            renderDataGrid('#junk_window', appState.junkList, cols.junk, 'path', true);
        });
    });

    document.querySelector('#repair_window .primary-btn')?.addEventListener('click', () => {
        if (!window.pywebview) return;
        window.pywebview.api.scan_system_repair().then(list => renderDataGrid('#repair_window', list, cols.repair, 'value', true));
    });

    document.querySelector('#repair_window .danger-btn')?.addEventListener('click', () => {
        const checked = getCheckedValues('#repair_window');
        if (checked.length === 0 || !window.pywebview) return;
        window.pywebview.api.execute_system_repair(checked).then(() => {
            window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_repaired"), "info");
            renderDataGrid('#repair_window', [], cols.repair, 'value');
        });
    });

    ['whitelist_window', 'quarantine_window', 'popup_window', 'custom_protect_window'].forEach(id => {
        const listKeyMap = {
            'popup_window': 'block_list',
            'custom_protect_window': 'custom_rule',
            'whitelist_window': 'white_list',
            'quarantine_window': 'quarantine'
        };
        const listKey = listKeyMap[id];

        document.querySelector(`#${id} .modern-btn:not(.primary-btn)`)?.addEventListener('click', () => {
            const checked = getCheckedValues(`#${id}`);
            if (checked.length > 0 && window.pywebview) window.pywebview.api.remove_list_items(listKey, checked).then(refreshConfigLists);
        });
        
        if (id !== 'popup_window') {
            document.querySelector(`#${id} .primary-btn`)?.addEventListener('click', () => {
                window.pywebview?.api.select_files().then(files => {
                    if (files?.length > 0) window.pywebview.api.manage_named_list(listKey, files, 'add').then(refreshConfigLists);
                });
            });
        }
    });

    document.querySelector('#popup_window .primary-btn')?.addEventListener('click', (e) => {
        if (!window.pywebview) return;
        e.target.setAttribute('data-i18n', 'msg_click_target'); e.target.textContent = getMsg('msg_click_target'); e.target.disabled = true;
        window.pywebview.api.capture_popup_window().then(rule => {
            e.target.setAttribute('data-i18n', 'btn_add'); e.target.textContent = getMsg('btn_add'); e.target.disabled = false;
            if (rule) window.pywebview.api.add_popup_rule(rule).then(ok => ok && refreshConfigLists());
        });
    });

    document.querySelector('#taskmgr_window .primary-btn')?.addEventListener('click', () => {
        if (!window.pywebview) return;
        document.querySelectorAll('#taskmgr_window .manage-list-item input[type="checkbox"]:checked').forEach(cb => {
            if (cb.dataset.path && cb.dataset.path !== "path_unknown") window.pywebview.api.open_file_location(cb.dataset.path);
        });
    });

    document.querySelector('#taskmgr_window .danger-btn')?.addEventListener('click', () => {
        const cbs = document.querySelectorAll('#taskmgr_window .manage-list-item input[type="checkbox"]:checked');
        if (cbs.length > 0 && window.pywebview) {
            window.pywebview.api.show_confirm(getMsg("msg_end_proc_title"), getMsg("msg_end_proc_confirm")).then(res => {
                if (res) Promise.all(Array.from(cbs).map(cb => window.pywebview.api.kill_process(parseInt(cb.value)))).then(() => {
                    window.pywebview.api.get_process_list().then(procs => renderDataGrid('#taskmgr_window', procs.map(p => ({ name: p.name, pid: p.pid, path: (p.path && p.path !== "None" && p.path !== "Unknown") ? p.path : "path_unknown" })), cols.process, 'pid', false));
                });
            });
        }
    });

    document.querySelector('#log_export_window .primary-btn')?.addEventListener('click', () => {
        const checked = getCheckedValues('#log_export_window');
        if (checked.length === 0) return window.pywebview?.api.show_alert(getMsg("title_prompt"), getMsg("msg_sel_log_export"), "warning");
        window.pywebview?.api.export_logs(checked).then(res => res && window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_export_success"), "info"));
    });

    document.querySelector('#log_export_window .danger-btn')?.addEventListener('click', () => {
        const checked = getCheckedValues('#log_export_window');
        if (checked.length === 0 || !window.pywebview) return;
        window.pywebview.api.show_confirm(getMsg("title_prompt"), getMsg("msg_del_log_confirm")).then(res => {
            if (res) window.pywebview.api.clear_logs(checked).then(() => {
                window.pywebview.api.get_logs().then(logs => renderDataGrid('#log_export_window', logs.reverse().map(log => ({ time_str: `[${log.time_str}]`, level: log.level, action: log.action, source: log.source || '-', id: log.id })), cols.log, 'id', true));
                window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_log_deleted"), "info");
            });
        });
    });

    document.getElementById('minimize_button')?.addEventListener('click', () => window.pywebview?.api.minimize());
    document.getElementById('close_button')?.addEventListener('click', () => window.pywebview?.api.hide_window());

    const contextMenu = document.createElement('div');
    contextMenu.className = 'custom-context-menu';
    contextMenu.innerHTML = `<div class="custom-context-menu-item" id="ctx_open_location"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"></path></svg><span data-i18n="ctx_open_loc"></span></div>`;
    document.body.appendChild(contextMenu);
    let ctxTarget = null;

    document.addEventListener('contextmenu', (e) => {
        const li = e.target.closest('.manage-list-item');
        if (li) {
            const cb = li.querySelector('input[type="checkbox"]');
            if (cb && cb.dataset.path && cb.dataset.path !== "path_unknown") {
                e.preventDefault();
                ctxTarget = cb.dataset.path;
                const span = contextMenu.querySelector('span');
                span.textContent = getMsg('ctx_open_loc');
                contextMenu.style.left = `${e.clientX}px`;
                contextMenu.style.top = `${e.clientY}px`;
                contextMenu.classList.add('show');
                const rect = contextMenu.getBoundingClientRect();
                if (rect.right > window.innerWidth) contextMenu.style.left = `${window.innerWidth - rect.width - 5}px`;
                if (rect.bottom > window.innerHeight) contextMenu.style.top = `${window.innerHeight - rect.height - 5}px`;
                return;
            }
        }
        contextMenu.classList.remove('show');
    });
    document.addEventListener('click', (e) => { if (!e.target.closest('.custom-context-menu')) contextMenu.classList.remove('show'); });
    document.addEventListener('scroll', () => contextMenu.classList.remove('show'), true);
    document.getElementById('ctx_open_location').addEventListener('click', () => {
        if (window.pywebview && ctxTarget) window.pywebview.api.open_file_location(ctxTarget);
        contextMenu.classList.remove('show');
    });

    initI18nKeys();

    const bindSettingAction = (key, action) => {
        const item = Array.from(document.querySelectorAll('#about_window .list-item, #setting_window .list-item')).find(el => {
            const h2 = el.querySelector('h2');
            return h2 && h2.getAttribute('data-i18n') === key;
        });
        
        if (item) {
            const btn = item.querySelector('button');
            
            if (btn) {
                btn.addEventListener('click', action);
            } else {
                item.style.cursor = 'pointer';
                item.dataset.action = key;
                item.addEventListener('click', action);
            }
        }
    };

    bindSettingAction('web_official', () => window.pywebview?.api.open_website());
    bindSettingAction('update_check', () => {
        window.pywebview?.api.check_update().then(res => {
            if (res.error) window.pywebview.api.show_alert(getMsg("title_error"), getMsg("msg_update_fail"), "error");
            else if (res.has_update) window.pywebview.api.show_confirm(getMsg("title_prompt"), `${getMsg("msg_new_version")} ${res.latest}\n(${res.current} -> ${res.latest})`).then(ok => ok && window.pywebview.api.open_url(res.url));
            else window.pywebview.api.show_alert(getMsg("title_prompt"), `${getMsg("msg_latest_version")} ${res.current}`, "info");
        });
    });
    bindSettingAction('opt_reset', () => {
        window.pywebview?.api.show_confirm(getMsg("title_prompt"), getMsg("opt_reset_desc")).then(res => {
            if (res) window.pywebview.api.reset_config().then(() => window.pywebview.api.show_alert(getMsg("title_prompt"), getMsg("msg_reset_success"), "info"));
        });
    });

    document.querySelectorAll('select.modern-select').forEach(buildCustomSelectElement);
    renderDataGrid('#scan_window', appState.virusResults, cols.virus, 'path', true);
    renderDataGrid('#taskmgr_window', [], cols.process, 'pid', false);
    renderDataGrid('#junk_window', [], cols.junk, 'path', true);
    renderDataGrid('#repair_window', [], cols.repair, 'value', true);
    renderDataGrid('#whitelist_window', [], cols.pathOnly, 'path', false);
    renderDataGrid('#quarantine_window', [], cols.pathOnly, 'path', false);
    renderDataGrid('#custom_protect_window', [], cols.pathOnly, 'path', false);
    renderDataGrid('#popup_window', [], cols.popup, 'value', false);
    renderDataGrid('#log_export_window', [], cols.log, 'id', true);

    window.addEventListener('pywebviewready', () => {
        window.pywebview.api.get_config().then(cfg => {
            const theme = cfg.theme || "white_switch";
            const lang = cfg.language || "english_switch";
            appState.firstLaunch = cfg.first_launch;
            applyTheme(theme);
            translateText(lang);
            updateCustomSelectUI('theme_select', theme);
            updateCustomSelectUI('lang_select', lang);

            const switchMap = ["process_switch", "document_switch", "system_switch", "driver_switch", "network_switch", "sensitive_switch", "extension_switch", "cloud_switch", "context_switch"];
            document.querySelectorAll('.toggle-switch input').forEach((toggle, index) => {
                if (appState.firstLaunch) { 
                    toggle.checked = false; 
                    toggle.disabled = true; 
                } else if (switchMap[index]) {
                    toggle.checked = !!cfg[switchMap[index]];
                }
            });
            
            window.pywebview.api.init_ui_ready();
        }).catch(err => {
            console.error("Config load failed:", err);
            window.pywebview.api.init_ui_ready();
        });
    });

    window.onEngineReady = async () => {
        if (!appState.firstLaunch) return;
        await window.pywebview.api.update_config("first_launch", false);
        const switchMap = ["process_switch", "document_switch", "system_switch", "driver_switch", "network_switch", "sensitive_switch", "extension_switch", "cloud_switch", "context_switch"];
        const seq = ["cloud_switch", "process_switch", "document_switch", "system_switch", "network_switch", "driver_switch"];
        
        for (const key of seq) {
            const index = switchMap.indexOf(key);
            if (index !== -1) {
                const toggle = document.querySelectorAll('.toggle-switch input')[index];
                if (toggle) {
                    toggle.checked = true;
                    try {
                        const res = await window.pywebview.api.update_config(key, true);
                        if (res !== undefined && res !== null) toggle.checked = res;
                    } catch { toggle.checked = false; } 
                    finally { toggle.disabled = false; }
                    await new Promise(r => setTimeout(r, 200));
                }
            }
        }
        document.querySelectorAll('.toggle-switch input').forEach(t => t.disabled = false);
        appState.firstLaunch = false;
    };
});