function openTrust(evt, Analysis){
    var i, Analysis, tablinks;
    Analysis = document.getElementsByClassName("Analysis");
        for (i = 0; i < Analysis.length; i++) {
        Analysis[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName("tablinks");
        for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
  }
  document.getElementById(InfoType).style.display = "block";
  document.getElementById("defaultOpen").click();
  evt.currentTarget.className += " active";
}