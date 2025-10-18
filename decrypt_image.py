from pathlib import Path
import struct

# Define file paths
src = Path("aes.bmp.enc")
dst = Path("aes_header_fixed.bmp")

# Read encrypted file
data = src.read_bytes()

# Analyse size and infer dimensions
file_size = len(data)
print(f"File size: {file_size} bytes")

pixel_data_size = file_size - 54
print(f"Pixel data size: {pixel_data_size} bytes")

width, height, bpp = 640, 480, 24

# Build valid BMP header
bfType = b'BM'
bfSize = file_size
bfReserved1 = 0
bfReserved2 = 0
bfOffBits = 54

# BITMAPINFOHEADER (40 bytes)
biSize = 40
biWidth = width
biHeight = height
biPlanes = 1
biBitCount = bpp
biCompression = 0
biSizeImage = pixel_data_size
biXPelsPerMeter = 2835
biYPelsPerMeter = 2835
biClrUsed = 0
biClrImportant = 0

# Pack headers (little-endian)
file_header = struct.pack('<2sIHHI', bfType, bfSize, bfReserved1, bfReserved2, bfOffBits)
info_header = struct.pack('<IIIHHIIIIII',
    biSize, biWidth, biHeight, biPlanes, biBitCount,
    biCompression, biSizeImage, biXPelsPerMeter, biYPelsPerMeter,
    biClrUsed, biClrImportant
)

# Combine new header + encrypted pixel data (skip old header)
fixed_bmp = file_header + info_header + data[54:]

# Write new file
dst.write_bytes(fixed_bmp)
print(f"Header fixed BMP written to: {dst}")