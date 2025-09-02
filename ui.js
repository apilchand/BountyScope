
const CSS_CLASSES = {
    DISABLED_LINK: 'disabled-link',
    COPY_SUCCESS: 'is-copied',
    COPY_FAILURE: 'is-failed',
};

function createCliToolHtml(tool, step) {
    const checkboxHtml = step.isResource
        ? ''
        : `<label class="flex items-center cursor-pointer pt-1" onclick="event.stopPropagation()">
               <input type="checkbox" data-phase-id="${step.phase}" data-tool-name="${tool.name}" class="phase-checkbox tool-checkbox" disabled>
           </label>`;

    return `
    <div class="tool-container bg-neutral-900 border border-neutral-800 p-4 rounded-lg group transition-all duration-300 hover:border-neutral-700">
        <div class="flex justify-between items-start mb-3">
            <div class="flex items-start gap-4 flex-1">
                ${checkboxHtml}
                <div class="w-10 h-10 rounded-md bg-neutral-800 flex items-center justify-center flex-shrink-0"><i class="ph-bold ph-terminal text-neutral-400 text-xl"></i></div>
                <div class="flex-1">
                    <p class="text-white font-bold flex items-center gap-2">
                        <span>${tool.name}</span>
                        ${tool.url ? `<a href="${tool.url}" target="_blank" rel="noopener noreferrer" class="text-neutral-500 hover:text-white transition-colors" title="Visit tool homepage" onclick="event.stopPropagation()"><i class="ph-bold ph-info text-sm"></i></a>` : ''}
                    </p>
                    <p class="text-neutral-400 text-sm">${tool.description}</p>
                </div>
            </div>
            <button class="copy-btn ${CSS_CLASSES.DISABLED_LINK} bg-neutral-800 hover:bg-neutral-700 text-neutral-300 text-xs font-medium py-2 px-3 rounded-md flex items-center gap-2 transition-colors active:scale-95 ml-2" aria-label="Copy ${tool.name} command"><i class="ph-bold ph-copy text-sm"></i><span>Copy</span></button>
        </div>
        <div class="bg-black rounded-md ml-10">
            <input type="text"
                class="command-input w-full bg-transparent p-3 text-[#00d4ff] text-sm font-mono leading-relaxed border-0 focus:ring-0"
                data-command-template="${tool.command}"
                placeholder="Set target to see command..."
                disabled>
        </div>
    </div>`;
}

function createGuiToolHtml(tool) {
    const linkHref = tool.noTarget ? `href="${tool.url}"` : `href="#" data-url-template="${tool.url}"`;
    const linkClass = tool.noTarget ? 'recon-link-no-target' : `recon-link ${CSS_CLASSES.DISABLED_LINK}`;
    return `
        <a ${linkHref} target="_blank" rel="noopener noreferrer" class="tool-container ${linkClass} group bg-neutral-900 border border-neutral-800 p-4 rounded-lg flex items-center justify-between transition-all duration-300 hover:border-neutral-700 hover:bg-neutral-800/50">
            <div class="flex items-center gap-4">
                <div class="w-10 h-10 rounded-md bg-neutral-800 flex items-center justify-center flex-shrink-0"><i class="ph-bold ph-arrow-square-out text-neutral-400 text-xl"></i></div>
                <div>
                   <h4 class="font-bold text-white group-hover:accent-text transition-colors flex items-center gap-2">
                        <span>${tool.name}</span>
                        ${tool.url ? `<a href="${tool.url}" target="_blank" rel="noopener noreferrer" class="text-neutral-500 hover:text-white transition-colors" title="Visit tool homepage" onclick="event.stopPropagation()"><i class="ph-bold ph-info text-sm"></i></a>` : ''}
                   </h4>
                   <p class="text-neutral-400 text-sm">${tool.description}</p>
                </div>
            </div>
            <i class="ph-bold ph-arrow-right text-xl text-neutral-500 group-hover:text-white group-hover:translate-x-1 transition-all"></i>
        </a>`;
}

export function renderFramework(reconSteps, reconGrid) {
    const fragment = document.createDocumentFragment();
    reconSteps.forEach((step, index) => {
        const phaseCard = document.createElement('div');
        phaseCard.className = 'phase-card themed-container themed-container-hover rounded-xl transition-all duration-300 animate-fade-in';
        phaseCard.style.animationDelay = `${index * 0.05}s`;
        phaseCard.dataset.phaseId = step.phase;

        const allTags = step.tools.flatMap(tool => tool.tags || []).join(' ');
        phaseCard.dataset.tags = allTags;

        const toolsHtml = step.tools.map(tool => {
            return tool.type === 'gui' ? createGuiToolHtml(tool) : createCliToolHtml(tool, step);
        }).join('');

        const checkboxHtml = step.isResource
            ? `<div class="flex items-center justify-center w-10 h-10 pt-1"><i class="ph-bold ph-books text-neutral-500 text-2xl"></i></div>`
            : `<label class="flex items-center cursor-pointer pt-1" onclick="event.stopPropagation()" title="Select all tools in this phase">
                 <input type="checkbox" data-phase-id="${step.phase}" class="phase-checkbox phase-select-all-checkbox" disabled>
               </label>`;

        phaseCard.innerHTML = `
            <button class="accordion-button w-full flex justify-between items-start p-5 text-left group cursor-pointer" aria-expanded="false">
                <div class="flex items-start gap-4">
                    ${checkboxHtml}
                    <div>
                        <h3 class="text-xl font-bold text-white flex items-center gap-3">
                            <i class="${step.icon} text-2xl accent-text"></i>
                            <span>${step.title}</span>
                            <div id="dep-warning-${step.phase}" class="dep-warning hidden">
                                <i class="ph-fill ph-warning-circle text-2xl" style="color: var(--warning-color);"></i>
                                <span class="dep-tooltip"></span>
                            </div>
                        </h3>
                        <p class="text-neutral-400 text-sm mt-2">${step.description}</p>
                    </div>
                </div>
                <div class="flex items-center gap-4 flex-shrink-0 pl-4">
                     <span class="bg-neutral-800 text-neutral-300 px-3 py-1 rounded-full text-xs font-medium">${step.tools.length} tools</span>
                    <i class="accordion-arrow ph-bold ph-caret-right text-2xl text-neutral-500 transition-transform duration-300"></i>
                </div>
            </button>
            <div class="accordion-content px-5 pb-5">
                <div class="grid grid-cols-1 gap-4 pt-4 border-t border-neutral-800">
                   ${toolsHtml}
                </div>
            </div>
        `;
        fragment.appendChild(phaseCard);
    });
    reconGrid.appendChild(fragment);
}

export function renderTagFilters(reconSteps, tagFilterContainer) {
    const allTags = new Set(reconSteps.flatMap(step => step.tools.flatMap(tool => tool.tags || [])));
    const sortedTags = Array.from(allTags).sort();

    const tagsHtml = sortedTags.map(tag =>
        `<button class="tag-filter-btn text-xs font-medium py-1.5 px-3 rounded-md transition-colors active:scale-95" data-tag="${tag}">${tag}</button>`
    ).join('');
    tagFilterContainer.innerHTML = tagsHtml;
}
