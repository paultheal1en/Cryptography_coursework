from pybloom_live import BloomFilter

def VBFVerify(VBF, value):
    """
    Check if a value exists in the Bloom Filter.

    Args:
        VBF (BloomFilter): An instance of Bloom Filter.
        value (Any): The value to check in the Bloom Filter.

    Returns:
        int: Returns 1 if the value might be in the Bloom Filter, otherwise returns 0.
    """
    if value in VBF:
        return 1
    return 0

def VBFAdd(VBF, value):
    """
    Add a value to the Bloom Filter.

    Args:
        VBF (BloomFilter): An instance of Bloom Filter.
        value (Any): The value to add to the Bloom Filter.

    Returns:
        None
    """
    VBF.add(value)
