import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import sys

def model1(filepath):
    if '.csv' in filepath:
        data = pd.read_csv(filepath)
    elif '.xlsx' in filepath:
        data = pd.read_excel(filepath)
    else:
        print('Invalid File Format! Only .csv and .xlsx files are Accepted!')
    
    print('\n\n\DATA SAMPLE\n\n')
    print(data.head())

    print('\n\nDATA DESCRIPTION\n\n')
    print(f'\nThis Data has Total of {data.shape[1]} Columns and {data.shape[0]} Observations.\n\n')
    print(round(data.describe().T, 2))

if __name__ == "__main__":
    filepath = sys.argv[1]
    model1(filepath)