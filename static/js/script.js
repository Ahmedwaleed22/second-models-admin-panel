var amount = document.getElementById("amount");
function toggle() {
  if (amount.value > 50000) {
    location.href = "/reportform";
  } else {
    alert("Enter a valid amount");
  }
}
