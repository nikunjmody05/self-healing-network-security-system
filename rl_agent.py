import random
import joblib


# ============================================================
# RL AGENT — Q-LEARNING
# ============================================================

class RLAgent:

    def __init__(
        self,
        alpha=0.1,
        gamma=0.9,
        epsilon=1.0,
        epsilon_min=0.05,
        epsilon_decay=0.995
    ):

        # ----------------------------------------------------
        # Q-TABLE
        # ----------------------------------------------------

        self.q_table = {}


        # ----------------------------------------------------
        # SECURITY ACTION SPACE
        # ----------------------------------------------------

        self.actions = [
            "ALLOW",
            "ALERT",
            "BLOCK"
        ]


        # ----------------------------------------------------
        # Q-LEARNING PARAMETERS
        # ----------------------------------------------------

        self.alpha = alpha

        self.gamma = gamma


        # ----------------------------------------------------
        # EXPLORATION PARAMETERS
        # ----------------------------------------------------

        self.epsilon = epsilon

        self.epsilon_min = epsilon_min

        self.epsilon_decay = epsilon_decay


        # ----------------------------------------------------
        # TRAINING STATISTICS
        # ----------------------------------------------------

        self.training_rewards = []

        self.episode_rewards = []


    # ========================================================
    # STATE REPRESENTATION
    # ========================================================

    def get_state(
        self,
        prediction,
        confidence
    ):

        # ----------------------------------------------------
        # Confidence buckets:
        #
        # 0.50 - 0.59 -> 5
        # 0.60 - 0.69 -> 6
        # 0.70 - 0.79 -> 7
        # 0.80 - 0.89 -> 8
        # 0.90 - 1.00 -> 9
        #
        # State example:
        #
        # (0, 9)
        # = BENIGN prediction
        # = very high confidence
        #
        # (1, 8)
        # = ATTACK prediction
        # = high confidence
        # ----------------------------------------------------

        confidence = max(
            0.0,
            min(
                1.0,
                float(confidence)
            )
        )


        conf_bucket = min(
            int(confidence * 10),
            9
        )


        return (
            int(prediction),
            conf_bucket
        )


    # ========================================================
    # INITIALIZE STATE
    # ========================================================

    def _initialize_state(
        self,
        state
    ):

        if state not in self.q_table:

            self.q_table[state] = {

                action: 0.0

                for action in self.actions
            }


    # ========================================================
    # ACTION SELECTION
    # ========================================================

    def choose_action(
        self,
        state,
        training=True
    ):

        self._initialize_state(
            state
        )


        # ====================================================
        # TRAINING MODE — EPSILON GREEDY
        # ====================================================

        if training:

            # ------------------------------------------------
            # Exploration
            # ------------------------------------------------

            if random.random() < self.epsilon:

                return random.choice(
                    self.actions
                )


        # ====================================================
        # EXPLOITATION
        # ====================================================
        #
        # During evaluation:
        #
        # training = False
        #
        # No random exploration is performed.
        #
        # We always select the action with the highest
        # learned Q-value.
        #
        # Using max() over self.actions also gives us
        # deterministic tie-breaking.
        #
        # ====================================================

        q_values = self.q_table[
            state
        ]


        best_action = max(

            self.actions,

            key=lambda action:
                q_values[action]
        )


        return best_action


    # ========================================================
    # Q-LEARNING UPDATE
    # ========================================================

    def update_q(
        self,
        state,
        action,
        reward,
        next_state,
        done=False
    ):

        # ----------------------------------------------------
        # Ensure current state exists
        # ----------------------------------------------------

        self._initialize_state(
            state
        )


        # ----------------------------------------------------
        # Current Q-value
        # ----------------------------------------------------

        current_q = self.q_table[
            state
        ][
            action
        ]


        # ====================================================
        # FUTURE REWARD
        # ====================================================

        if done:

            # ------------------------------------------------
            # Terminal decision.
            #
            # No future state contributes to the current
            # Q-value.
            #
            # This is what we currently use for independent
            # CIC-IDS2017 network-flow decisions.
            # ------------------------------------------------

            max_next_q = 0.0


        else:

            # ------------------------------------------------
            # Sequential environment.
            #
            # This path can later be used when we model
            # actual multi-stage APT state transitions.
            # ------------------------------------------------

            self._initialize_state(
                next_state
            )


            max_next_q = max(

                self.q_table[
                    next_state
                ].values()
            )


        # ====================================================
        # Q-LEARNING TARGET
        # ====================================================

        target = (

            reward

            + self.gamma
            * max_next_q
        )


        # ====================================================
        # Q-VALUE UPDATE
        # ====================================================

        self.q_table[
            state
        ][
            action
        ] += (

            self.alpha

            * (

                target

                - current_q
            )
        )


    # ========================================================
    # EPSILON DECAY
    # ========================================================

    def decay_epsilon(
        self
    ):

        self.epsilon = max(

            self.epsilon_min,

            self.epsilon
            * self.epsilon_decay
        )


    # ========================================================
    # SET EVALUATION MODE
    # ========================================================

    def set_evaluation_mode(
        self
    ):

        self.epsilon = 0.0


    # ========================================================
    # GET BEST ACTION
    # ========================================================

    def get_best_action(
        self,
        state
    ):

        # ----------------------------------------------------
        # Useful for evaluation / policy inspection.
        # ----------------------------------------------------

        self._initialize_state(
            state
        )


        q_values = self.q_table[
            state
        ]


        return max(

            self.actions,

            key=lambda action:
                q_values[action]
        )


    # ========================================================
    # SAVE Q-TABLE
    # ========================================================

    def save_q_table(
        self,
        filename="q_table.pkl"
    ):

        joblib.dump(
            self.q_table,
            filename
        )


        print(
            f"\nQ-table saved to: "
            f"{filename}"
        )


    # ========================================================
    # LOAD Q-TABLE
    # ========================================================

    def load_q_table(
        self,
        filename="q_table.pkl"
    ):

        self.q_table = joblib.load(
            filename
        )


        print(
            f"\nQ-table loaded from: "
            f"{filename}"
        )


    # ========================================================
    # DISPLAY LEARNED POLICY
    # ========================================================

    def display_policy(
        self
    ):

        print("\n")

        print(
            "=" * 70
        )

        print(
            "                 LEARNED RL POLICY"
        )

        print(
            "=" * 70
        )


        for state in sorted(
            self.q_table
        ):

            q_values = self.q_table[
                state
            ]


            best_action = max(

                self.actions,

                key=lambda action:
                    q_values[action]
            )


            formatted_values = [

                round(
                    q_values[action],
                    2
                )

                for action
                in self.actions
            ]


            print(

                f"State {state} -> "

                f"{best_action} | "

                f"Q-values: "

                f"{formatted_values}"
            )


        print(
            "=" * 70
        )


# ============================================================
# REWARD FUNCTION
# ============================================================

def get_reward(
    true_label,
    action
):

    # ========================================================
    # ATTACK TRAFFIC
    # ========================================================

    if true_label == 1:

        # ----------------------------------------------------
        # Correct containment
        # ----------------------------------------------------

        if action == "BLOCK":

            return 10


        # ----------------------------------------------------
        # Attack detected/escalated,
        # but not automatically contained
        # ----------------------------------------------------

        elif action == "ALERT":

            return 2


        # ----------------------------------------------------
        # Most dangerous outcome:
        # attack allowed through
        # ----------------------------------------------------

        elif action == "ALLOW":

            return -15


    # ========================================================
    # BENIGN TRAFFIC
    # ========================================================

    else:

        # ----------------------------------------------------
        # Correct decision
        # ----------------------------------------------------

        if action == "ALLOW":

            return 5


        # ----------------------------------------------------
        # Unnecessary SOC workload / alert fatigue
        # ----------------------------------------------------

        elif action == "ALERT":

            return -2


        # ----------------------------------------------------
        # False blocking of legitimate traffic
        # ----------------------------------------------------

        elif action == "BLOCK":

            return -10


    # ========================================================
    # FALLBACK
    # ========================================================

    return -10


# ============================================================
# MODULE READY
# ============================================================

print(
    "RL Agent Ready."
)