window.addEventListener('load', function () {
  const p = document.getElementById("userInputWarn");
  function checkUserInput() {
    alert(p.innerHTML)
    const input = document.getElementsByClassName("inputDiv");
    p.style.display = "block";
    for (let i = 0; i < input.length; i++) {
        input[i].style.borderColor = "red";
    }
    setTimeout(() => {
        p.style.display = "none";
        for (let i = 0; i < input.length; i++) {
        input[i].style.borderColor = "#ccc";
    }
    }, 1500)
  };
  if (p.innerHTML) {
      checkUserInput();
  };


  document.querySelectorAll(".toggleP").forEach((element) => element.addEventListener('click', (event) => {
      const id = event.target.id;
      const eye = document.getElementsByClassName("eye")[id];
      const slashEye = document.getElementsByClassName("slashEye")[id];
      if(eye.style.display != "none") {
          eye.style.display = "none";
          slashEye.style.display = "block";
          document.getElementsByClassName("accountPasswordInput")[id].type ="text";
      } else {
          eye.style.display = "block";
          slashEye.style.display = "none";
          document.getElementsByClassName("accountPasswordInput")[id].type ="password";
      }
  }))
  });