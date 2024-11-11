from tabulate import tabulate

def output_table(data, headers):
    print(tabulate(data, headers=headers, tablefmt="fancy_grid"))