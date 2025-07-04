const keyboard = document.querySelector('.keyboard')
const layout = [
        'Q','W','E','R','T','Y','U','I','O','P','Backspace',
          'A','S','D','F','G','H','J','K','L','Enter',
            'Z','X','C','V','B','N','M', 
]
const LFs = ['Backspace','Enter']

for (let i of layout) {
    var key = document.createElement('button')
    key.classList.add('key')
    
    if (i === "Backspace") {
        key.classList.add('backspace')
        key.addEventListener('click', () => {
            BackspaceHandler()
        })
    } else if (i === "Enter") {
        key.classList.add('enter')
        key.addEventListener('click', () => {
            if (focusIndex === wordLen-1) {
                CheckAnsw()
            }
        })
    } else {
        key.innerText = i
        key.id = i
        key.addEventListener('click', () => {
            if (focusIndex!==wordLen-1){
                focus.value = i
                ChangeFocus(true)
            } else if (focus.value == '') {
                focus.value = i
            }
        })
    }

    keyboard.append(key)
    if (LFs.includes(i)) {
        var br = document.createElement('br')
        keyboard.append(br)
    }
}
