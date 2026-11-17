class ResponseEngine:

    def __init__(self):
        print("Response Engine Ready.")

    def execute(self, action, severity):

        # -----------------------------------------
        # ALLOW
        # -----------------------------------------
        if action == "ALLOW":

            return {
                "action": "ALLOW",
                "response": "TRAFFIC ALLOWED",
                "status": "MONITORING",
                "containment": False
            }

        # -----------------------------------------
        # ALERT
        # -----------------------------------------
        elif action == "ALERT":

            return {
                "action": "ALERT",
                "response": "SECURITY ALERT GENERATED",
                "status": "UNDER MONITORING",
                "containment": False
            }

        # -----------------------------------------
        # BLOCK
        # -----------------------------------------
        elif action == "BLOCK":

            return {
                "action": "BLOCK",
                "response": "TRAFFIC BLOCKED",
                "status": "CONTAINED",
                "containment": True
            }

        # -----------------------------------------
        # UNKNOWN ACTION
        # -----------------------------------------
        else:

            return {
                "action": action,
                "response": "UNKNOWN ACTION",
                "status": "ERROR",
                "containment": False
            }