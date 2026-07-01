import pytest

from util.suri_util import get_drop_rate

def binary_search(function, mini: float, maxi: float, drop_rate: float, delta: float, max_cycles: int, repetitions: int) -> float:
    """
    Core function of binary_search. Handles binary_search algorithm.
    If implementing custom testing function, use 1 for higher multiplier
    and -1 for lower multiplier.
    Inputs:
        function -> pointer to a function that runs test run
        mini -> value to search from to (multiplier) [FLOAT]
        maxi -> value to search up to (multiplier) [FLOAT]
        drop_rate -> drop rate to converge to in % <0, 100> [FLOAT]
        delta -> maximum allowed difference between jumps [FLOAT]
        max_cycles -> maximum amount of cycles for main loop [INT]
        repetitions -> how many times should Suricata be tested per multiplier [INT]
    Outputs:
        Multiplier value [FLOAT] -> Output value is the closest sub drop_rate
        found multiplier. If no sub drop_rate value is found, outputs the closest
        value it has found so far.
    """

    if (max_cycles <= 0):
        max_cycles = 1
        print("[WARNING] Binary search: Maximum number of cycles was lower than 1. Setting to 1.")

    if mini < 0:
        mini = 0
        print("[WARNING] Binary search: Minimum multiplier was below 0. Setting to 0.")

    if maxi < 0:
        maxi = 0
        print("[WARNING] Binary search: Maximum multiplier was below 0. Setting to 0.")

    if mini > maxi:
        mini, maxi = maxi, mini
        print("[WARNING] Binary search: Maximum multiplier is lower than minimum. Swapping values")

    if drop_rate < 0:
        drop_rate = 0
        print("[WARNING] Binary search: Drop rate is below 0%. Setting to 0%.")

    if drop_rate > 100:
        drop_rate = 100
        print("[WARNING] Binary search: Drop rate is above 100%. Setting to 100%.")

    if repetitions < 1:
        repetitions = 1
        print("[WARNING] Binary search: Repetition value is lower than 1. Setting to 1.")

    max_multiplier = mini

    for i in range(1, max_cycles + 1):
        # check if we have converged
        if ((maxi - mini) < delta):
            break

        print(f"\n[PROGRESS] ------ Cycle: {i}/{max_cycles} ------- [PROGRESS]")

        mid = (mini + maxi) / 2
        check = test_function(drop_rate, mid, repetitions, function)

        # check if we can go faster
        if (check == 1):
            mini = mid
            max_multiplier = mid

        # check if we must go slower
        elif (check == -1):
            maxi = mid

        else:
            pytest.fail(f"Unexpected value from test_function: {check}")

    return max_multiplier


def test_function(target: float, multiplier: float, repetitions: int, function):
    """
    Function that determines if we have found our determined drop rate.
    Inputs:
        target -> Drop rate % to converge to <0 - 100> [FLOAT]
        multiplier -> multiplier to run test with [FLOAT]
        repetitions -> number of repetitions for testing [INT]
        function -> function that calls the test
    Outputs:
        1 -> increase multiplier
       -1 -> decrease multiplier
    """
    drop_rate_arr = []
    for i in range(1, repetitions + 1):
        print(f"\n[PROGRESS] Repetition number: {i}/{repetitions} of multiplier {multiplier}.")
        function(multiplier)
        drop_rate_addition = get_drop_rate()
        if drop_rate_addition == -1.0:
            pytest.fail(f"Error occurred while getting drop rate: {drop_rate_addition}")
        drop_rate_arr.append(drop_rate_addition)
        print(f"[INFO] Drop rate: {drop_rate_arr[-1]:.4f}% for repetition {i}.")

    drop_rate_avg = sum(drop_rate_arr) / len(drop_rate_arr)
    print(f"\n[INFO] Average drop rate for multiplier {multiplier}: {drop_rate_avg:.4f}%.")

    if drop_rate_avg > target:
        return -1
    return 1 
