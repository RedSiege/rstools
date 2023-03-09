/*
 mike@redsiege.com

 Technique valid as of 03/09/2023

 1. Perform a Google search for the target company
    1a. site:linkedin.com/in "Company Name"
 2. Scroll through search results until all results are exhausted
 3. Open the Developer tools console and paste in the Javascript below
 4. Copy results from console 

*/

var employees = [];
employees = employees.concat(document.getElementsByTagName("h3"));
for(var i=0;i<employees[0].length;i++){
	console.log(employees[0][i].innerHTML)
}
