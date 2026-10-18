import pydivert

with pydivert.WinDivert("outbound") as w:
    print("OUTBOUND SUCCESS")