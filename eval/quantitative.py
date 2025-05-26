import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Load and sort CSV data by 'manual' values
data = pd.read_csv('quantitative.csv')
data_sorted = data.sort_values(by='manual', ascending=True)

# Extract sorted data
devices = data_sorted['name']
manual = data_sorted['manual']
generated = data_sorted['generated']

# Set bar width and positions
x = np.arange(len(devices))
bar_width = 0.35

# Plot bars
plt.figure(figsize=(10, 6))
plt.bar(x - bar_width/2, manual, width=bar_width, label='Manual')
plt.bar(x + bar_width/2, generated, width=bar_width, label='Generated')

# Labeling
plt.xlabel('Device')
plt.ylabel('Number of patterns')
# plt.title('Manual vs Generated Profiles per Device')
plt.xticks(x, devices, rotation=45, ha='right')
plt.legend()

# Layout adjustment
plt.tight_layout()

# Show plot
#plt.show()

plt.savefig('quantitative.pdf')