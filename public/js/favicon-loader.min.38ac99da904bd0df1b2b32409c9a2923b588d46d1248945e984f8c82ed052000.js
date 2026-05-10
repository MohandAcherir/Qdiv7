document.addEventListener("DOMContentLoaded",function(){const e={"github.com":"invert","atom.io":"invert","openai.com":"invert","chatgpt.com":"invert",default:"bg"};function o(){const e=document.createElement("style");e.textContent=`
            .link-favicon {
                width: 16px;
                height: 16px;
                vertical-align: middle;
                margin-right: 0.3em;
                transition: all 0.2s ease-in-out;
                box-sizing: border-box;
                border-radius: 3px;
            }
            /* 深色模式下的背景策略 */
            .favicon-dark-bg {
                background-color: rgba(250, 250, 250, 1);
                padding: 1px; /* 细微的内边距让效果更好 */
            }
            
            /* GitHub备用反色策略：如果白色背景失效 */
            .favicon-dark-invert {
                filter: invert(1) brightness(1.5) contrast(1.5) !important;
                background-color: transparent !important;
            }
        `,document.head.appendChild(e)}function i(){return document.documentElement.getAttribute("data-theme")||(window.matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light")}function t(t,n){const o=i(),s=e[n]||e.default;t.classList.remove("favicon-dark-bg","favicon-dark-invert"),o==="dark"&&(s==="bg"?t.classList.add("favicon-dark-bg"):s==="invert"&&t.classList.add("favicon-dark-invert"))}function n(){document.querySelectorAll(".link-favicon").forEach(e=>{const n=e.dataset.domain;n&&t(e,n)})}function s(e){if(e.dataset.faviconProcessed)return;try{const r=new URL(e.href),n=r.hostname;console.log(`Processing favicon for domain: ${n}`);const s=document.createElement("img");s.className="link-favicon",s.alt=`${n} icon`,s.dataset.domain=n,s.loading="lazy";const i=[`https://www.google.com/s2/favicons?domain=${n}&sz=32`,`https://icons.duckduckgo.com/ip3/${n}.ico`,`https://favicon.io/${n}`];let o=0;const a=()=>{o<i.length?(console.log(`Trying favicon source ${o+1} for ${n}: ${i[o]}`),s.src=i[o++]):(console.warn(`All favicon sources failed for ${n}`),s.style.display="none")};s.onload=function(){console.log(`Successfully loaded favicon for ${n} from source ${o}`),t(this,n)},s.onerror=function(){console.warn(`Failed to load favicon for ${n} from source ${o}: ${i[o-1]}`),a()},e.dataset.faviconProcessed="true",e.insertBefore(s,e.firstChild),a()}catch(t){console.error("Error creating favicon for:",e.href,t),e.dataset.faviconProcessed="true"}}function a(){document.querySelectorAll('a[href^="http"]').forEach(e=>{if(e.querySelector("img, svg")||e.closest(".no-favicon"))return;s(e)})}function r(){const e=new MutationObserver(n);e.observe(document.documentElement,{attributes:!0,attributeFilter:["data-theme"]}),window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change",n)}o(),a(),r(),window.addFaviconToLink=s})