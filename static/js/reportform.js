// need
var land = document.getElementById("land");
var machinery = document.getElementById("machinery");
var shed = document.getElementById("shed");
var expenditure = document.getElementById("expenditure");
var computer = document.getElementById("computer");
var furniture = document.getElementById("furniture");
var electricity = document.getElementById("electricity");
var racks = document.getElementById("racks");
var vehicle = document.getElementById("vehicle");
var software = document.getElementById("software");
var group_need_total = document.getElementById("group-need-total");
var totalneed = document.getElementById("totalneed");

// expense
var rent = document.getElementById("rent");
var salary = document.getElementById("salary");
var purchase = document.getElementById("purchase");
var stationary = document.getElementById("stationary");
var water = document.getElementById("water");
var repair = document.getElementById("repair");
var cost = document.getElementById("cost");
var postal = document.getElementById("postal");
var marketing = document.getElementById("marketing");
var misc = document.getElementById("misc");
var group_expense_total = document.getElementById("group-expense-total");
var totalexp = document.getElementById("totalexpense");

var bussbtn = document.getElementById("bussbtn");
var needbtn = document.getElementById("needbtn");
var expensebtn = document.getElementById("expensebtn");
var capbtn = document.getElementById("capbtn");
// need
function land_expand() {
  if (land.style.display != "block") {
    land.style.display = "block";
  } else {
    land.style.display = "none";
  }
}
function mach_expand() {
  if (machinery.style.display != "block") {
    machinery.style.display = "block";
  } else {
    machinery.style.display = "none";
  }
}
function shed_expand() {
  if (shed.style.display != "block") {
    shed.style.display = "block";
  } else {
    shed.style.display = "none";
  }
}

function pexpand() {
  if (expenditure.style.display != "block") {
    expenditure.style.display = "block";
  } else {
    expenditure.style.display = "none";
  }
}
function comp_expand() {
  if (computer.style.display != "block") {
    computer.style.display = "block";
  } else {
    computer.style.display = "none";
  }
}
function fur_expand() {
  if (furniture.style.display != "block") {
    furniture.style.display = "block";
  } else {
    furniture.style.display = "none";
  }
}
function elect_expand() {
  if (electricity.style.display != "block") {
    electricity.style.display = "block";
  } else {
    electricity.style.display = "none";
  }
}
function racks_expand() {
  if (racks.style.display != "block") {
    racks.style.display = "block";
  } else {
    racks.style.display = "none";
  }
}
function vehicle_expand() {
  if (vehicle.style.display != "block") {
    vehicle.style.display = "block";
  } else {
    vehicle.style.display = "none";
  }
}
function soft_expand() {
  if (software.style.display != "block") {
    software.style.display = "block";
  } else {
    software.style.display = "none";
  }
}
// expense
function rent_expand() {
  if (rent.style.display != "block") {
    rent.style.display = "block";
  } else {
    rent.style.display = "none";
  }
}
function salary_expand() {
  if (salary.style.display != "block") {
    salary.style.display = "block";
  } else {
    salary.style.display = "none";
  }
}
function purchase_expand() {
  if (purchase.style.display != "block") {
    purchase.style.display = "block";
  } else {
    purchase.style.display = "none";
  }
}

function stationary_expand() {
  if (stationary.style.display != "block") {
    stationary.style.display = "block";
  } else {
    stationary.style.display = "none";
  }
}
function water_expand() {
  if (water.style.display != "block") {
    water.style.display = "block";
  } else {
    water.style.display = "none";
  }
}
function repair_expand() {
  if (repair.style.display != "block") {
    repair.style.display = "block";
  } else {
    repair.style.display = "none";
  }
}
function cost_expand() {
  if (cost.style.display != "block") {
    cost.style.display = "block";
  } else {
    cost.style.display = "none";
  }
}
function postal_expand() {
  if (postal.style.display != "block") {
    postal.style.display = "block";
  } else {
    postal.style.display = "none";
  }
}
function marketing_expand() {
  if (marketing.style.display != "block") {
    marketing.style.display = "block";
  } else {
    marketing.style.display = "none";
  }
}
function misc_expand() {
  if (misc.style.display != "block") {
    misc.style.display = "block";
  } else {
    misc.style.display = "none";
  }
}

function buss() {
  var group_bussiness = document.getElementById("group-bussiness");
  var name = document.getElementById("name");
  if (group_bussiness.style.display != "block" && name.value != "") {
    group_bussiness.style.display = "block";
    bussbtn.style.display = "none";
  }
}
function need() {
  var group_need = document.getElementById("group-need");
  var manufacturing = document.getElementById("manufacturing");
  var service = document.getElementById("service");
  var agriculture = document.getElementById("agriculture");
  var other = document.getElementById("other");
  if (
    group_need.style.display != "block" &&
    (manufacturing.checked ||
      service.checked ||
      agriculture.checked ||
      other.checked)
  ) {
    group_need.style.display = "block";
    needbtn.style.display = "none";
  } else {
    alert("please select the option");
  }
}
function expense() {
  var group_expense = document.getElementById("group-expense");

  if (
    group_expense.style.display != "block" &&
    (land.value > 0 ||
      machinery.value > 0 ||
      shed.value > 0 ||
      expenditure.value > 0 ||
      computer.value > 0 ||
      furniture.value > 0 ||
      electricity.value > 0 ||
      racks.value > 0 ||
      vehicle.value > 0 ||
      software.value > 0)
  ) {
    total = String(
      Number(land.value) +
        Number(machinery.value) +
        Number(shed.value) +
        Number(expenditure.value) +
        Number(computer.value) +
        Number(furniture.value) +
        Number(electricity.value) +
        Number(racks.value) +
        Number(vehicle.value) +
        Number(software.value)
    );
    sum = eval(total);
    group_need_total.style.display = "block";
    group_expense.style.display = "block";
    expensebtn.style.display = "none";
    totalneed.innerHTML = sum;
  } else {
    alert("please select an option");
  }
}
function cap() {
  var group_capital = document.getElementById("group-capital");
  if (
    group_capital.style.display != "block" &&
    (rent.value > 0 ||
      salary.value > 0 ||
      purchase.value > 0 ||
      stationary.value > 0 ||
      water.value > 0 ||
      repair.value > 0 ||
      cost.value > 0 ||
      postal.value > 0 ||
      marketing.value > 0 ||
      misc.value > 0)
  ) {
    total = String(
      Number(rent.value) +
        Number(salary.value) +
        Number(purchase.value) +
        Number(stationary.value) +
        Number(water.value) +
        Number(repair.value) +
        Number(cost.value) +
        Number(postal.value) +
        Number(marketing.value) +
        Number(misc.value)
    );
    sum = eval(total);
    group_capital.style.display = "block";
    group_expense_total.style.display = "block";
    capbtn.style.display = "none";
    totalexp.innerHTML = sum;
  } else {
    alert("please select an option");
  }
}
document.getElementById("final").addEventListener("click", function (e) {
  e.preventDefault();
  var capital = document.getElementById("capital");
  const queryString = window.location.search;
  const urlParams = new URLSearchParams(queryString);
  const answers = urlParams.get("answers");
  const modelID = urlParams.get("model");

  if (capital.value != "") {
    window.location = `/results?model=${modelID}&answers=${answers}&data=${JSON.stringify(
      getData()
    )}&capital=${capital.value}`;
  } else {
    alert("Data not completed!");
  }
});
