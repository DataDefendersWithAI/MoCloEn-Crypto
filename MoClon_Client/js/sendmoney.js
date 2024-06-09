import { ajaxHandler } from "./ajaxHandler";
$(document).ready(function() {
    // Send money
    let db = false;
    $("#send-money").submit(function(event) {
        event.preventDefault();
        if(db == true) return;
        db = true;
        let amount =filterXSS( $("#amount").val());
        let recipient = filterXSS($("#recipient").val());
        ajaxHandler.transaction_create(recipient, amount).then((response) => {db = true;});
    });
});