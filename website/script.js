const tabs = document.querySelectorAll('.tab');
const image = document.querySelector('#showcase-img');
const title = document.querySelector('#panel-title');
const description = document.querySelector('#panel-desc');
function selectTab(tab) {
  tabs.forEach(item => {
    const selected = item === tab;
    item.classList.toggle('active', selected);
    item.setAttribute('aria-selected', String(selected));
    item.tabIndex = selected ? 0 : -1;
  });
  image.src = `../docs/screenshots/${tab.dataset.image}`;
  image.alt = tab.dataset.alt;
  title.textContent = tab.dataset.title;
  description.textContent = tab.dataset.desc;
}
tabs.forEach((tab, index) => {
  tab.tabIndex = index === 0 ? 0 : -1;
  tab.addEventListener('click', () => selectTab(tab));
  tab.addEventListener('keydown', event => {
    let next = index;
    if (event.key === 'ArrowDown' || event.key === 'ArrowRight') next = (index + 1) % tabs.length;
    else if (event.key === 'ArrowUp' || event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = tabs.length - 1;
    else return;
    event.preventDefault();
    selectTab(tabs[next]);
    tabs[next].focus();
  });
});
