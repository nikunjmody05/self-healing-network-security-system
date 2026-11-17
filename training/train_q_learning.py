"""Q-learning training script that produced the shipped models/q_table.pkl
(30 episodes, 2,000 flows, epsilon 1.0 -> 0.05). Writes to models/retrained/."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import project_config as cfg  # noqa: E402

OUT_DIR = cfg.BASE_DIR / "models" / "retrained"  # never overwrites models/*.pkl
OUT_DIR.mkdir(parents=True, exist_ok=True)

import random
import numpy as np
import joblib
import pandas as pd
import matplotlib.pyplot as plt

from rl_agent import RLAgent, get_reward


# ============================================================
# CONFIGURATION
# ============================================================

DATA_PATH = cfg.DATA_PATH

MODEL_FILE = cfg.MODEL_FILE
Q_TABLE_FILE = OUT_DIR / "q_table.pkl"

EPISODES = 30
SAMPLES_PER_EPISODE = 2000

RANDOM_STATE = 42


# ============================================================
# REPRODUCIBILITY
# ============================================================

random.seed(
    RANDOM_STATE
)

np.random.seed(
    RANDOM_STATE
)


# ============================================================
# LOAD RANDOM FOREST MODEL
# ============================================================

print("\nLoading Random Forest model...")

model = joblib.load(
    MODEL_FILE
)

print("Random Forest model loaded.")


# ============================================================
# LOAD DATASET
# ============================================================

print("\nLoading CIC-IDS2017 dataset...")

df = pd.read_parquet(
    DATA_PATH
)

print(
    f"Dataset loaded: "
    f"{len(df):,} records"
)


# ============================================================
# CREATE BINARY TARGET
# ============================================================

df["target"] = df["Label"].apply(
    lambda x:
        0
        if x == "Benign"
        else 1
)


# ============================================================
# SAMPLE TRAINING DATA
# ============================================================

df_sample = df.sample(
    n=SAMPLES_PER_EPISODE,
    random_state=RANDOM_STATE
).reset_index(
    drop=True
)


# ============================================================
# FEATURES AND TARGET
# ============================================================

X = df_sample.drop(
    columns=[
        "Label",
        "ClassLabel",
        "target"
    ]
)

y = df_sample[
    "target"
].values


# ============================================================
# DATASET SUMMARY
# ============================================================

benign_samples = int(
    (y == 0).sum()
)

attack_samples = int(
    (y == 1).sum()
)


print("\nTraining sample created.")

print(
    f"Total Samples  : "
    f"{len(X)}"
)

print(
    f"Benign Samples : "
    f"{benign_samples}"
)

print(
    f"Attack Samples : "
    f"{attack_samples}"
)


# ============================================================
# PRECOMPUTE ML PREDICTIONS
# ============================================================
#
# Random Forest predictions do not change between RL episodes.
# Therefore there is no reason to call model.predict() 60,000
# times.
#
# We calculate the ML outputs once and reuse them throughout
# RL training.
#
# ============================================================

print(
    "\nPrecomputing Random Forest predictions..."
)

predictions = model.predict(
    X
)

probabilities = model.predict_proba(
    X
)

confidences = np.max(
    probabilities,
    axis=1
)

print(
    "Random Forest predictions ready."
)


# ============================================================
# INITIALIZE RL AGENT
# ============================================================

agent = RLAgent(
    alpha=0.1,
    gamma=0.9,
    epsilon=1.0,
    epsilon_min=0.05,
    epsilon_decay=0.90
)


# ============================================================
# TRAINING HISTORY
# ============================================================

episode_rewards = []

epsilon_history = []

allow_history = []

alert_history = []

block_history = []


# ============================================================
# TRAINING HEADER
# ============================================================

print("\n")
print("=" * 72)

print(
    "                    RL TRAINING STARTED"
)

print("=" * 72)

print(
    f"Episodes            : "
    f"{EPISODES}"
)

print(
    f"Samples / Episode   : "
    f"{SAMPLES_PER_EPISODE}"
)

print(
    f"Initial Epsilon     : "
    f"{agent.epsilon}"
)

print(
    f"Minimum Epsilon     : "
    f"{agent.epsilon_min}"
)

print(
    f"Decay Rate          : "
    f"{agent.epsilon_decay}"
)

print(
    "Decision Model      : "
    "Independent Flow Decisions"
)

print("=" * 72)


# ============================================================
# MULTI-EPISODE RL TRAINING
# ============================================================

for episode in range(
    EPISODES
):

    # --------------------------------------------------------
    # EPISODE METRICS
    # --------------------------------------------------------

    total_reward = 0

    allow_count = 0
    alert_count = 0
    block_count = 0


    # ========================================================
    # PROCESS ALL TRAINING SAMPLES
    # ========================================================

    for i in range(
        len(X)
    ):

        # ----------------------------------------------------
        # ML DETECTION RESULT
        # ----------------------------------------------------

        pred = predictions[
            i
        ]

        confidence = confidences[
            i
        ]


        # ----------------------------------------------------
        # RL STATE
        # ----------------------------------------------------

        state = agent.get_state(
            prediction=pred,
            confidence=confidence
        )


        # ----------------------------------------------------
        # RL ACTION
        # ----------------------------------------------------

        action = agent.choose_action(
            state,
            training=True
        )


        # ----------------------------------------------------
        # REWARD
        # ----------------------------------------------------

        reward = get_reward(
            true_label=y[i],
            action=action
        )


        # ----------------------------------------------------
        # Q-LEARNING UPDATE
        # ----------------------------------------------------
        #
        # IMPORTANT:
        #
        # Each CIC-IDS2017 flow in this training sample is
        # treated as an independent security decision.
        #
        # The next randomly sampled network flow is NOT a
        # meaningful consequence of the current response.
        #
        # Therefore:
        #
        # done = True
        #
        # This prevents Q-values from unrelated flows from
        # being propagated into the current decision.
        #
        # Later, when we model sequential APT behaviour,
        # next_state will represent an actual security-state
        # transition.
        #
        # ----------------------------------------------------

        agent.update_q(
            state=state,
            action=action,
            reward=reward,
            next_state=state,
            done=True
        )


        # ----------------------------------------------------
        # REWARD TRACKING
        # ----------------------------------------------------

        total_reward += reward


        # ----------------------------------------------------
        # ACTION TRACKING
        # ----------------------------------------------------

        if action == "ALLOW":

            allow_count += 1

        elif action == "ALERT":

            alert_count += 1

        elif action == "BLOCK":

            block_count += 1


    # ========================================================
    # END OF EPISODE
    # ========================================================

    episode_rewards.append(
        total_reward
    )

    epsilon_history.append(
        agent.epsilon
    )

    allow_history.append(
        allow_count
    )

    alert_history.append(
        alert_count
    )

    block_history.append(
        block_count
    )

    agent.training_rewards.append(
        total_reward
    )


    # --------------------------------------------------------
    # DISPLAY EPISODE RESULT
    # --------------------------------------------------------

    print(
        f"Episode "
        f"{episode + 1:02d}/{EPISODES} | "
        f"Reward: {total_reward:6d} | "
        f"Epsilon: {agent.epsilon:.4f} | "
        f"ALLOW: {allow_count:4d} | "
        f"ALERT: {alert_count:4d} | "
        f"BLOCK: {block_count:4d} | "
        f"States: {len(agent.q_table)}"
    )


    # --------------------------------------------------------
    # DECAY EPSILON
    # --------------------------------------------------------

    agent.decay_epsilon()


# ============================================================
# SAVE TRAINED Q-TABLE
# ============================================================

agent.save_q_table(
    Q_TABLE_FILE
)


# ============================================================
# DISPLAY LEARNED POLICY
# ============================================================

agent.display_policy()


# ============================================================
# TRAINING SUMMARY
# ============================================================

print("\n")
print("=" * 72)

print(
    "                    TRAINING COMPLETE"
)

print("=" * 72)

print(
    f"Episodes Completed    : "
    f"{EPISODES}"
)

print(
    f"Training Samples      : "
    f"{SAMPLES_PER_EPISODE}"
)

print(
    f"Final Epsilon         : "
    f"{agent.epsilon:.4f}"
)

print(
    f"Final Q-table Size    : "
    f"{len(agent.q_table)} states"
)

print(
    f"Best Episode Reward   : "
    f"{max(episode_rewards)}"
)

print(
    f"Final Episode Reward  : "
    f"{episode_rewards[-1]}"
)

print(
    f"Final ALLOW Count     : "
    f"{allow_history[-1]}"
)

print(
    f"Final ALERT Count     : "
    f"{alert_history[-1]}"
)

print(
    f"Final BLOCK Count     : "
    f"{block_history[-1]}"
)

print("=" * 72)


# ============================================================
# SAVE TRAINING HISTORY
# ============================================================

training_history = pd.DataFrame({

    "episode":
        range(
            1,
            EPISODES + 1
        ),

    "reward":
        episode_rewards,

    "epsilon":
        epsilon_history,

    "allow":
        allow_history,

    "alert":
        alert_history,

    "block":
        block_history
})


training_history.to_csv(
    OUT_DIR / "rl_training_history.csv",
    index=False
)


print(
    "\nTraining history saved to: "
    "rl_training_history.csv"
)


# ============================================================
# SAVE TRAINING SUMMARY
# ============================================================

training_summary = pd.DataFrame(
    [
        {
            "episodes":
                EPISODES,

            "samples_per_episode":
                SAMPLES_PER_EPISODE,

            "benign_samples":
                benign_samples,

            "attack_samples":
                attack_samples,

            "initial_epsilon":
                1.0,

            "final_epsilon":
                round(
                    agent.epsilon,
                    4
                ),

            "epsilon_min":
                agent.epsilon_min,

            "epsilon_decay":
                agent.epsilon_decay,

            "alpha":
                agent.alpha,

            "gamma":
                agent.gamma,

            "q_table_states":
                len(agent.q_table),

            "best_episode_reward":
                max(
                    episode_rewards
                ),

            "final_episode_reward":
                episode_rewards[-1],

            "final_allow":
                allow_history[-1],

            "final_alert":
                alert_history[-1],

            "final_block":
                block_history[-1]
        }
    ]
)


training_summary.to_csv(
    OUT_DIR / "rl_training_summary.csv",
    index=False
)


print(
    "Training summary saved to: "
    "rl_training_summary.csv"
)


# ============================================================
# EPISODE REWARD CURVE
# ============================================================

plt.figure(
    figsize=(10, 5)
)

plt.plot(
    range(
        1,
        EPISODES + 1
    ),
    episode_rewards,
    marker="o",
    linewidth=2
)

plt.title(
    "Q-Learning Episode Reward",
    fontsize=13,
    fontweight="bold"
)

plt.xlabel(
    "Episode"
)

plt.ylabel(
    "Total Reward"
)

plt.grid(
    axis="both",
    linestyle="--",
    alpha=0.3
)

plt.tight_layout()

plt.savefig(
    OUT_DIR / "rl_episode_rewards.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()


# ============================================================
# EPSILON DECAY CURVE
# ============================================================

plt.figure(
    figsize=(10, 5)
)

plt.plot(
    range(
        1,
        EPISODES + 1
    ),
    epsilon_history,
    marker="o",
    linewidth=2
)

plt.title(
    "Q-Learning Exploration Decay",
    fontsize=13,
    fontweight="bold"
)

plt.xlabel(
    "Episode"
)

plt.ylabel(
    "Epsilon"
)

plt.grid(
    axis="both",
    linestyle="--",
    alpha=0.3
)

plt.tight_layout()

plt.savefig(
    OUT_DIR / "rl_epsilon_decay.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()


# ============================================================
# ACTION DISTRIBUTION DURING TRAINING
# ============================================================

plt.figure(
    figsize=(10, 5)
)

episodes = range(
    1,
    EPISODES + 1
)

plt.plot(
    episodes,
    allow_history,
    label="ALLOW",
    linewidth=2
)

plt.plot(
    episodes,
    alert_history,
    label="ALERT",
    linewidth=2
)

plt.plot(
    episodes,
    block_history,
    label="BLOCK",
    linewidth=2
)

plt.title(
    "RL Action Distribution During Training",
    fontsize=13,
    fontweight="bold"
)

plt.xlabel(
    "Episode"
)

plt.ylabel(
    "Action Count"
)

plt.legend()

plt.grid(
    axis="both",
    linestyle="--",
    alpha=0.3
)

plt.tight_layout()

plt.savefig(
    OUT_DIR / "rl_training_actions.png",
    dpi=300,
    bbox_inches="tight"
)

plt.show()


# ============================================================
# OUTPUT SUMMARY
# ============================================================

print("\n")
print("=" * 72)

print(
    "                    OUTPUTS GENERATED"
)

print("=" * 72)

print(
    "1. q_table.pkl"
)

print(
    "2. rl_training_history.csv"
)

print(
    "3. rl_training_summary.csv"
)

print(
    "4. rl_episode_rewards.png"
)

print(
    "5. rl_epsilon_decay.png"
)

print(
    "6. rl_training_actions.png"
)

print("=" * 72)