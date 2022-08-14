// bussiness
var manufacturing = document.getElementById("manufacturing");
var service = document.getElementById("service");
var agriculture = document.getElementById("agriculture");
var bussiness = document.getElementById("bussiness");

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

var username = document.getElementById("name");
var capital = document.getElementById("capital");

const getData = () => {
  let data = {
    name: username.value,
    manufacturing: manufacturing.checked,
    service: service.checked,
    agriculture: agriculture.checked,
    other: other.checked,
    land: Number(land.value),
    machinery: Number(machinery.value),
    shed: Number(shed.value),
    expenditure: Number(expenditure.value),
    computer: Number(computer.value),
    furniture: Number(furniture.value),
    electricity: Number(electricity.value),
    racks: Number(racks.value),
    vehicle: Number(vehicle.value),
    software: Number(software.value),
    rent: Number(rent.value),
    salary: Number(salary.value),
    purchase: Number(purchase.value),
    water: Number(water.value),
    repair: Number(repair.value),
    cost: Number(cost.value),
    postal: Number(postal.value),
    marketing: Number(marketing.value),
    misc: Number(misc.value),
  };

  return data;
};
