// AxonFlow Execution Viewer - Client-side application
const App = {
    state: { offset: 0, limit: 20, total: 0 },

    // Initialize the list view
    init() {
        document.getElementById('btn-filter').addEventListener('click', () => {
            this.state.offset = 0;
            this.loadExecutions();
        });
        document.getElementById('btn-prev').addEventListener('click', () => {
            this.state.offset = Math.max(0, this.state.offset - this.state.limit);
            this.loadExecutions();
        });
        document.getElementById('btn-next').addEventListener('click', () => {
            this.state.offset += this.state.limit;
            this.loadExecutions();
        });
        this.loadExecutions();
    },

    // Fetch and render the executions list
    async loadExecutions() {
        const status = document.getElementById('filter-status').value;
        const workflow = document.getElementById('filter-workflow').value;
        this.state.limit = parseInt(document.getElementById('filter-limit').value, 10);

        const params = new URLSearchParams();
        params.set('limit', this.state.limit);
        params.set('offset', this.state.offset);
        if (status) params.set('status', status);
        if (workflow) params.set('workflow_id', workflow);

        this.showLoading(true);
        this.hideError();

        try {
            const resp = await fetch('/api/v1/unified/executions?' + params.toString());
            if (!resp.ok) throw new Error('Failed to load executions: ' + resp.statusText);
            const data = await resp.json();
            this.state.total = data.total || 0;
            this.renderTable(data.executions || []);
            this.renderPagination();
        } catch (err) {
            this.showError(err.message);
        } finally {
            this.showLoading(false);
        }
    },

    // Render the executions table
    renderTable(executions) {
        const tbody = document.getElementById('executions-table');
        const empty = document.getElementById('empty-state');

        if (executions.length === 0) {
            tbody.innerHTML = '';
            empty.classList.remove('hidden');
            return;
        }
        empty.classList.add('hidden');

        tbody.innerHTML = executions.map(e => {
            const duration = e.duration || '-';
            const workflow = e.name || '-';
            const completedSteps = (e.steps || []).filter(s => s.status === 'completed').length;
            const steps = completedSteps + '/' + (e.total_steps || 0);
            const cost = '$' + (e.actual_cost_usd || 0).toFixed(4);
            const started = this.formatTime(e.started_at);
            const id = e.execution_id || '';
            const idShort = id.length > 32 ? id.substring(0, 29) + '...' : id;

            return '<tr class="clickable-row" onclick="App.viewExecution(\'' + id + '\')">' +
                '<td class="px-4 py-3 text-sm font-mono">' + this.esc(idShort) + '</td>' +
                '<td class="px-4 py-3 text-sm">' + this.esc(workflow) + '</td>' +
                '<td class="px-4 py-3 text-sm"><span class="status-badge status-' + e.status + '">' + e.status + '</span></td>' +
                '<td class="px-4 py-3 text-sm">' + steps + '</td>' +
                '<td class="px-4 py-3 text-sm">' + duration + '</td>' +
                '<td class="px-4 py-3 text-sm">' + cost + '</td>' +
                '<td class="px-4 py-3 text-sm text-gray-500">' + started + '</td>' +
                '</tr>';
        }).join('');
    },

    // Update pagination controls
    renderPagination() {
        const info = document.getElementById('pagination-info');
        const btnPrev = document.getElementById('btn-prev');
        const btnNext = document.getElementById('btn-next');

        const from = this.state.total > 0 ? this.state.offset + 1 : 0;
        const to = Math.min(this.state.offset + this.state.limit, this.state.total);
        info.textContent = 'Showing ' + from + '-' + to + ' of ' + this.state.total;

        btnPrev.disabled = this.state.offset === 0;
        btnNext.disabled = this.state.offset + this.state.limit >= this.state.total;
    },

    // Navigate to execution detail
    viewExecution(id) {
        window.location.href = '/ui/executions/detail.html?id=' + encodeURIComponent(id);
    },

    // Load and render a single execution detail
    async loadExecution(id) {
        const loading = document.getElementById('loading');
        if (loading) loading.classList.remove('hidden');

        try {
            const resp = await fetch('/api/v1/unified/executions/' + encodeURIComponent(id));
            if (!resp.ok) throw new Error('Failed to load execution: ' + resp.statusText);
            const data = await resp.json();
            this.renderDetail(data);

            // Set up export button
            document.getElementById('btn-export').addEventListener('click', () => {
                this.exportExecution(id);
            });
        } catch (err) {
            this.showError(err.message);
        } finally {
            if (loading) loading.classList.add('hidden');
        }
    },

    // Render execution detail view
    // Unified API returns a flat ExecutionStatus object (not wrapped in summary/steps).
    renderDetail(exec) {
        const s = exec.summary || exec;
        document.getElementById('summary-id').textContent = s.execution_id || s.request_id || '-';
        document.getElementById('summary-workflow').textContent = s.name || s.workflow_name || '-';
        document.getElementById('summary-status').innerHTML =
            '<span class="status-badge status-' + s.status + '">' + s.status + '</span>';
        document.getElementById('summary-duration').textContent = s.duration || (s.duration_ms != null ? this.formatDuration(s.duration_ms) : '-');
        const completedSteps = (s.steps || []).filter(st => st.status === 'completed').length;
        document.getElementById('summary-steps').textContent =
            completedSteps + '/' + (s.total_steps || 0) + ' completed';
        const totalTokens = (s.steps || []).reduce((sum, st) => sum + (st.tokens_in || 0) + (st.tokens_out || 0), 0);
        document.getElementById('summary-tokens').textContent =
            totalTokens.toLocaleString();
        document.getElementById('summary-cost').textContent =
            '$' + (s.actual_cost_usd || s.total_cost_usd || 0).toFixed(4);
        document.getElementById('summary-started').textContent = this.formatTime(s.started_at);

        if (s.error || s.error_message) {
            const errEl = document.getElementById('summary-error');
            errEl.textContent = s.error || s.error_message;
            errEl.classList.remove('hidden');
        }

        // Render steps — unified API includes steps directly in the response
        const steps = exec.steps || s.steps || [];
        const stepsList = document.getElementById('steps-list');
        stepsList.innerHTML = steps.map((step, i) => {
            const duration = step.duration || (step.duration_ms != null ? this.formatDuration(step.duration_ms) : '-');
            const provider = step.provider ? step.provider + '/' + step.model : '';
            const hasTokens = step.tokens_in != null || step.tokens_out != null;
            const tokens = hasTokens ?
                (step.tokens_in ?? 0) + ' in / ' + (step.tokens_out ?? 0) + ' out' : '';

            let detailHtml = '';
            if (provider) detailHtml += '<div><strong>Provider:</strong> ' + this.esc(provider) + '</div>';
            if (tokens) detailHtml += '<div><strong>Tokens:</strong> ' + tokens + '</div>';
            if (step.cost_usd != null) detailHtml += '<div><strong>Cost:</strong> $' + step.cost_usd.toFixed(4) + '</div>';
            if (step.error || step.error_message) {
                detailHtml += '<div class="text-red-600 mt-1"><strong>Error:</strong> ' + this.esc(step.error || step.error_message) + '</div>';
            }
            if (step.decision && step.decision !== 'allow') {
                detailHtml += '<div class="mt-1"><strong>Gate Decision:</strong> ' + this.esc(step.decision) + '</div>';
                if (step.decision_reason) detailHtml += '<div class="ml-4 text-sm">' + this.esc(step.decision_reason) + '</div>';
            }
            if (step.approval_status) {
                detailHtml += '<div class="mt-1"><strong>Approval:</strong> ' + this.esc(step.approval_status) + '</div>';
                if (step.approved_by) detailHtml += '<div class="ml-4 text-sm">By: ' + this.esc(step.approved_by) + '</div>';
            }
            const policyEvents = step.policies_triggered || step.policies_matched;
            if (policyEvents && policyEvents.length > 0) {
                detailHtml += '<div class="mt-1"><strong>Policies Matched:</strong></div>';
                policyEvents.forEach(pe => {
                    if (typeof pe === 'string') {
                        detailHtml += '<div class="ml-4 text-sm">' + this.esc(pe) + '</div>';
                    } else {
                        detailHtml += '<div class="ml-4 text-sm">[' + this.esc(pe.action || '') + '] ' +
                            this.esc(pe.policy_name || pe.policy_id || '') + (pe.reason ? ' - ' + this.esc(pe.reason) : '') + '</div>';
                    }
                });
            }
            if (step.input) {
                detailHtml += '<div class="mt-2"><strong>Input:</strong></div>' +
                    '<div class="io-block">' + this.esc(this.prettyJSON(step.input)) + '</div>';
            }
            if (step.output) {
                detailHtml += '<div class="mt-2"><strong>Output:</strong></div>' +
                    '<div class="io-block">' + this.esc(this.prettyJSON(step.output)) + '</div>';
            }

            return '<div class="step-card">' +
                '<div class="step-header" onclick="App.toggleStep(' + i + ')">' +
                    '<div class="flex items-center gap-3">' +
                        '<span class="text-sm font-medium text-gray-500">#' + (step.step_index || (i + 1)) + '</span>' +
                        '<span class="status-badge status-' + step.status + '">' + step.status + '</span>' +
                        '<span class="text-sm font-medium">' + this.esc(step.step_name) + '</span>' +
                    '</div>' +
                    '<div class="text-sm text-gray-500">' + duration + '</div>' +
                '</div>' +
                '<div class="step-detail" id="step-detail-' + i + '">' + detailHtml + '</div>' +
                '</div>';
        }).join('');
    },

    // Toggle step detail visibility
    toggleStep(index) {
        const el = document.getElementById('step-detail-' + index);
        if (el) el.classList.toggle('open');
    },

    // Export execution as JSON download
    async exportExecution(id) {
        try {
            const resp = await fetch('/api/v1/unified/executions/' + encodeURIComponent(id));
            if (!resp.ok) throw new Error('Export failed: ' + resp.statusText);
            const blob = await resp.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'execution-' + id + '.json';
            a.click();
            URL.revokeObjectURL(url);
        } catch (err) {
            alert('Export failed: ' + err.message);
        }
    },

    // Utility functions
    formatDuration(ms) {
        if (ms < 1000) return ms + 'ms';
        if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
        return (ms / 60000).toFixed(1) + 'm';
    },

    formatTime(iso) {
        if (!iso) return '-';
        const d = new Date(iso);
        return d.toLocaleString();
    },

    prettyJSON(obj) {
        try {
            if (typeof obj === 'string') return obj;
            return JSON.stringify(obj, null, 2);
        } catch (e) {
            return String(obj);
        }
    },

    esc(str) {
        const el = document.createElement('span');
        el.textContent = str;
        return el.innerHTML;
    },

    showLoading(show) {
        const el = document.getElementById('loading');
        if (el) el.classList.toggle('hidden', !show);
    },

    showError(msg) {
        const el = document.getElementById('error-state');
        const msgEl = document.getElementById('error-message');
        if (el && msgEl) {
            msgEl.textContent = msg;
            el.classList.remove('hidden');
        }
    },

    hideError() {
        const el = document.getElementById('error-state');
        if (el) el.classList.add('hidden');
    }
};
