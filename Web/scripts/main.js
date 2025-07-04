const line = document.createElement('div')
line.classList.add('line')

const letBox = document.createElement('div') // Let = Letter
const letInp = document.createElement('input')
letInp.type = "text"
letInp.disabled=true
letInp.classList.add('letbox')
// letInp.maxLength = 1
// letInp.setAttribute("oninput", "this.value = this.value.toUpperCase()")
letBox.append(letInp)

const html = document.querySelector('html')
const container = document.querySelector('.container')
const head = document.querySelector('h1')
const head2 = document.querySelector('h2')
const retry = document.querySelector('button')

const attempts = 6
const wordLen = 5

let current
let lines
let Word
let focus
let focusLine
let focusIndex

// Creating Grid
function CreateGrid () {
    for (let i = 0; i < attempts; i++) {
        var newLine = line.cloneNode(true)
        container.append(newLine)
    }

    lines = document.querySelectorAll('.line')
    lines.forEach( (l,i) => {
        for (j = 0; j < wordLen; j++) {
            var newLetBox = letBox.cloneNode(true)
            l.append(newLetBox)
        }
    })
}

function Start() {
    Word = Words[Math.floor(Math.random() *Words.length)] //Words from words.js
    CreateGrid()
    var br = document.createElement('br')
    container.append(br)

    FocusLine(0) // Setting first line focused
    current = 0
}

function CheckAnsw() {
    let answ = ''
    lines[current].childNodes.forEach( (iBox,i) => {
        var iInp = iBox.childNodes[0]
        answ+=iInp.value.toLowerCase()
    })
    if (answ.length === wordLen) {
        var NonRight = []
        for (let i = 0; i < wordLen; i++){
            if (answ[i] !== Word[i]) {
                NonRight[i] = Word[i]
            } 
        }
        lines[current].childNodes.forEach( (iBox,i) => {
            var key = document.querySelector(`#${answ[i].toUpperCase()}`)
            var iInp = iBox.childNodes[0]
            iInp.disabled = true
            iInp.classList.remove('current')
            if (answ[i] === Word[i]) {
                iInp.classList.add('right')
                key.classList.add('right')
                key.classList.remove('occurence')
            } else if (NonRight.includes(answ[i])) {
                iInp.classList.add('occurence')
                if (!Object.values(key.classList).includes('right')) {
                    key.classList.add('occurence')
                }
            } else {
                iInp.classList.add('wrong')
                if (!(Object.values(key.classList).includes('right') || Object.values(key.classList).includes('occurence'))) {
                    key.classList.add('wrong')
                }
            }

        })
        if (answ === Word) {
            head.innerText = 'Congratulations!'
            var msg
            if (current === 0) {msg=`You guessed the word in ${current+1} attempt!`} else {msg=`You guessed the word in ${current+1} attempts!`}
            head2.innerText = msg
            Finish()
        } else if (current < attempts-1) {
            current+=1
            FocusLine(current)
        } else {
            head.innerText = "Oops.. You lost.."
            head2.innerText = `The word was "${Word.charAt(0).toUpperCase() + Word.slice(1)}"`
            Finish()
        }
    }
}

function FocusLine(x) {
    focusLine = lines[x]
    focusIndex = 0
    lines[x].childNodes.forEach( (iBox) => {
        var iInp = iBox.childNodes[0]
        iInp.classList.add('current')
    })
    focus = lines[x].childNodes[focusIndex].childNodes[0]
    focus.classList.add('focus')

    try {html.removeEventListener('keydown', KeydownHandler)} catch {console.warn("KeydownHandler is not defined")} // Linking an Event Listener for new Line
    html.addEventListener('keydown', KeydownHandler)
}

function ChangeFocus(x) {
    focus.classList.remove('focus')
    if (x) {focusIndex+=1} else {focusIndex-=1}
    focus = focusLine.childNodes[focusIndex].childNodes[0]
    focus.classList.add('focus')
    focus.value = ''
}

function KeydownHandler(event) {
    if (event.code === "Backspace") {
        BackspaceHandler()
    } else if (event.code === "Enter" && focusIndex === wordLen-1) {
        CheckAnsw()
    } else if (event.code === `Key${event.key.toUpperCase()}`) {
        if (focusIndex!==wordLen-1){
            focus.value = event.key.toUpperCase()
            ChangeFocus(true)
        } else if (focus.value == '') {
            focus.value = event.key.toUpperCase()
        }
    }
}

function BackspaceHandler(){
    if (focusIndex > 0) {
        if (focusIndex === wordLen-1 && focus.value !== '') {focus.value=''} else {ChangeFocus(false)}
    }
}

function Finish() {
    retry.removeAttribute('hidden')
    keyboard.remove()
    focus = null

    for (let iline of lines) {
        if (iline !== focusLine) {
            iline.childNodes.forEach( (iLetBox) =>{
                var iLetInp = iLetBox.childNodes[0]
                if (iLetInp.classList.length === 0){
                    iLetInp.classList.add('wrong')
                }
            })
        } else {
            iline.childNodes[wordLen-1].childNodes[0].classList.remove('focus')
        }
    }
}

Start()
