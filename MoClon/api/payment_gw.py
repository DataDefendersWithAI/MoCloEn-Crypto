import random

def mock_payment_gateway():
    """
        Mock payment gateway
        :return: payment status
        {
            "status": "success"|"fail"
            "message": "Payment successful"|"Payment failed"
            "amount": 0
        }
        Drop rate: 
                success 90% | fail 10%
    """
    chance = random.randint(1,100)
    if chance <= 90:
        return {
            "status": "success",
            "message": "Payment successful",
        }
    else:
        return {
            "status": "fail",
            "message": "Payment failed",
        }