import { ajaxHandler } from "./ajaxHandler.js";
$(document).ready(function() {

    // Send money
    let db = false;
    $("#send-money").on("click",function(event) {
        event.preventDefault();
        if(db == true) return;
        db = true;
        let amount =filterXSS($("#amount").val());
        let recipient = filterXSS($("#recipient").val());
        let message = filterXSS($("#message").val());
        console.log(amount, recipient, message);
        ajaxHandler.transaction_create(recipient, amount, message).done(() => {db = true;});
    });
});