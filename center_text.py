import os

def center_text(text):
  """Centers text both horizontally and vertically in the terminal."""

  # Get terminal size
  rows, columns = os.popen('stty size', 'r').read().split()
  rows = int(rows)
  columns = int(columns)

  # Calculate center coordinates
  center_x = columns // 2 - len(text) // 2
  center_y = rows // 2

  # Clear the screen
  os.system('clear') 

  # Position the cursor to the center
  print("\033[{};{}H".format(center_y, center_x), end="") 

  # Print the text
  print(text)

# Example usage
text_to_center = "Hello, World!"
center_text(text_to_center)
