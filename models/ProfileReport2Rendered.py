import io
import sys
import base64
import numpy as np
import pandas as pd
from datetime import datetime as dt
import matplotlib.pyplot as plt
import warnings
import json
warnings.filterwarnings('ignore')

plt.rc('font', size=15)

style1 = {'selector':'table',
         'props': 'border: none; border-collapse: collapse; border-spacing: 0; color: black; font-size: 12px; table-layout: fixed;'}
style2 = {'selector':'',
         'props':''}
style3 = {'selector':'thead',
         'props':'border-bottom: 1px solid black; vertical-align: bottom;'}
style4 = {'selector':'tr th td',
         'props':'text-align: right; vertical-align: middle; padding: 0.5em 0.5em; line-height: normal; white-space: normal; max-width: none; border: none;'}
style5 = {'selector':'th',
         'props':'font-weight: bold;'}
style6 = {'selector':'tbody tr:nth-child(odd)',
         'props':'background: #f5f5f5;'}
style7 = {'selector':'tbody tr:hover',
         'props':'background: rgba(66, 165, 245, 0.2);'}

pandas_default_style = [style1, style2, style3, style4, style5, style6, style7]

def render_dataframe(df):
    return df.head().style.set_table_styles(pandas_default_style).to_html(header="true", table_id="table")

def render_plot(plt):
    pic_IObytes = io.BytesIO()
    plt.savefig(pic_IObytes,  format='png')
    pic_IObytes.seek(0)
    pic_hash = base64.b64encode(pic_IObytes.read())
    pic_IObytes.close()
    plt.close()
    print("<img height=\"400\" width=\"500\" src=\"data:image/png;base64, " + pic_hash.decode('utf-8') + "\"/>")


class TermLoan():
    def __init__(self, land=0, shed=0, machine=0, computer=0, furniture=0, electricity=0, storage=0, vehicle=0, software=0, other_exp=0):
        self.land = land
        self.shed = shed
        self.machine = machine
        self.computer = computer
        self.furniture = furniture
        self.electricity = electricity
        self.storage = storage
        self.vehicle = vehicle
        self.software = software
        self.other_exp = other_exp
        
    def dict_info(self):
        return {key:value for key, value in self.__dict__.items() if value}
    
    def project_cost(self):
        return sum(self.__dict__.values())
    
    naming_dict = {
    'land': 'Land',
    'shed':'Shed/Building /Tank',
    'machine':'Machinery',
    'computer':'Computers/printers/photocopier/other electronic gadgets, etc.',
    'furniture':'Furniture & fixtures',
    'electricity':'Electrification & Electricity Backup',
    'storage':'Racks & Storage',
    'vehicle':'Vehicle',
    'software':'Software purchase',
    'other_exp':'Other Initial Expenditure'
                }
    
    rate_dict = {
    'shed': 5,
    'machine': 15,
    'furniture':10,
    'storage': 10,
    'computer': 15,
    'other_exp': 15
                }

class WCLoan():
    def __init__(self, rent = 0, salary = 0, consumables = 0, stationary = 0, electric_water=0, repair = 0, transportation = 0, tele_internet = 0, market_ad = 0, insurance = 0, misc = 0):
        self.rent = rent
        self.salary = salary
        self.consumables = consumables
        self.stationary = stationary
        self.electric_water = electric_water
        self.repair = repair
        self.transportation = transportation
        self.tele_internet = tele_internet
        self.market_ad = market_ad
        self.misc = misc
    
    def dict_info(self):
        return {key:value for key, value in self.__dict__.items() if value}
    
    def monthly_expense(self):
        return sum(self.__dict__.values())
    
    exp_type1 = ['salary', 'consumables', 'electric_water', 'repair']
    
    exp_type2 = ['rent', 'stationary', 'transportation', 'tele_internet', 'market_ad', 'misc']
    
    naming_dict = {
    'rent':'Rented Building',
    'salary':'Salary',
    'consumables':'Purchase of consumables/ spare parts',
    'stationary':'Stationary expenses',
    'electric_water':'Electricity/Water Expense',
    'repair':'Repair and Maintenance Charges',
    'transportation':'Transportation Cost',
    'tele_internet':'Telephone/Postal & Internet Charges',
    'market_ad':'Marketing & Advertising Cost',
    'insurance':'Insurance Expense',
    'misc':'Miscellaneous Expenses'
                }

def str2float(row_str):
    return [float(ele) for ele in row_str.replace(',', '').split(' ')]

def create_row(start_num, multiplier, years):
    return [round(start_num*multiplier**i, 2) for i in range(years)]

def sum_list(*args):
    args = [arg for arg in args if arg]
    return [round(sum(x),2) for x in zip(*args)]

def subtract_list(l1, l2):
    if l1 and l2:
        return [round((x-y),2) for x, y in zip(l1, l2)]
    elif l1:
        return l1
    else:
        return [-ele for ele in l2]

def create_zeroes(n):
    return [0.00 for i in range(n)]

def create_date_cols(n):
    return [(dt.now() + pd.DateOffset(day=31, years=i)).strftime("%d/%m/%y") for i in range(1, n+1)]

def divide_list(l1, l2):
    if l1 and l2:
        return [round((x/y), 2) for x, y in zip(l1, l2)]
    else:
        return create_zeroes(n=len(l1) or len(l2))

def calc_ratio(l1, l2):
    '''
    Note: Put Big Value First in l1
    '''
    return [round((y-x)/y*100, 2) for x, y in zip(l1, l2)]


def project_at_a_glance(params_dict):
    # Project at a Glance
    params_dict['term_loan_contribution'] = params_dict['project_cost']*params_dict['marginal_money']
    params_dict['working_loan_contribution'] = params_dict['working_capital_loan']*params_dict['marginal_money']

    params_dict['stock_in_hand'] = round((params_dict['working_capital_loan'] + params_dict['working_loan_contribution'])*params_dict['stock_in_hand_perc'], 2)

    params_dict['working_expense'] = (params_dict['working_capital_loan'] + params_dict['working_loan_contribution']) - params_dict['stock_in_hand']
    params_dict['total_working_capital'] = params_dict['working_expense'] + params_dict['stock_in_hand']

    params_dict['term_loan'] = params_dict['project_cost'] - params_dict['term_loan_contribution']

    params_dict['total_project_cost'] = params_dict['project_cost'] + params_dict['total_working_capital']
    params_dict['promoter_contrbution'] = params_dict['term_loan_contribution'] + params_dict['working_loan_contribution']
    params_dict['total_bank_loan'] = params_dict['total_project_cost'] - params_dict['promoter_contrbution']
    
    project_at_a_glance_df = pd.DataFrame(
                                        [params_dict['no_of_employment'], params_dict['total_project_cost'], params_dict['project_cost'], params_dict['total_working_capital'], params_dict['total_bank_loan'], params_dict['promoter_contrbution'], params_dict['term_loan'], params_dict['working_capital_loan']],
                                        index = ['Nummber of employment', 'Total Project Cost', 'Fixed Capital', 'Working Capital', 'Total Bank Loan', 'Promoter(s) Contribution', 'Term Loan', 'Working Capital Loan']
                                        )
    return project_at_a_glance_df, params_dict

def project_cost_func(params_dict):
    project_cost_df = pd.DataFrame(params_dict['tl'].dict_info(), index=['Amount Rs.']).T.reset_index().reset_index().apply(lambda x:x.replace(params_dict['tl'].naming_dict))
    project_cost_df['level_0'] = range(1, project_cost_df.shape[0]+1)
    project_cost_df.columns = ['Sl No.', 'Items', 'Amount (₹)']\
    
    project_cost_df = project_cost_df.append({
            'Sl No.': project_cost_df.shape[0]+1,
            'Items' : 'Working Capital',
            'Amount (₹)': params_dict['working_capital_loan'] + params_dict['working_capital_loan']*params_dict['marginal_money']
                  }, ignore_index=True)
    
    project_cost_df = project_cost_df.append({
            'Sl No.': '',
            'Items' : 'Total',
            'Amount (₹)': project_cost_df['Amount (₹)'].sum()
                  }, ignore_index=True)

    return project_cost_df

def working_cap_comp(params_dict):    
    working_capital__computation_df = pd.DataFrame(
                                                    [[1, 'Consumables/ Stock in Hand', params_dict['stock_in_hand']],
                                                    [2, 'Working Expense', params_dict['working_expense']],
                                                    [3, 'Total Working Capital', params_dict['total_working_capital']],
                                                    [4, 'Own Contribution', params_dict['working_loan_contribution']],
                                                    [5, 'Working Capital Loan', params_dict['working_capital_loan']]],
                                                    columns= ['Sl. No.', 'Item', 'Amount']
                                                        )
    return working_capital__computation_df

def annual_revenue(params_dict):
    
    if dt.today().month >= 4:
        months = 16 - dt.today().month
    else:
        months = 4 - dt.today().month
        
    annual_revenue_df = pd.DataFrame(
                                    [[1, params_dict['product'], params_dict['rate'], params_dict['quantity'], months, params_dict['unit'], round(params_dict['rate']*params_dict['quantity']*months, 2)]],
                                    columns=['Sl.No', 'Item', 'Rate', 'Quantity', 'Month', 'Unit', 'Total']
                                    )
    
    params_dict['revenue'] = annual_revenue_df['Total'].sum()
    params_dict['revenue12'] = round(params_dict['rate']*params_dict['quantity']*12, 2)
    annual_revenue_df.loc[annual_revenue_df.shape[0]] = [np.nan, 'Total', np.nan,  np.nan, np.nan, np.nan, params_dict['revenue']]
    params_dict['months'] = months

    return annual_revenue_df, params_dict

def total_yearly_exp(params_dict):
                     
    total_yearly_exp_df = pd.DataFrame(params_dict['wc'].dict_info(), index=['Amount Rs.']).T.reset_index().reset_index().apply(lambda x:x.replace(params_dict['wc'].naming_dict))
    total_yearly_exp_df['level_0'] = range(1, total_yearly_exp_df.shape[0]+1)
                     
    total_yearly_exp_df.columns = ['Sl No.', 'Items', 'Amount (₹)']
    total_yearly_exp_df['Amount (₹)'] = total_yearly_exp_df['Amount (₹)']*params_dict['months']
                     
    total_yearly_exp_df = total_yearly_exp_df.append({
            'Sl No.': '',
            'Items' : 'Total',
            'Amount (₹)': total_yearly_exp_df['Amount (₹)'].sum()
                  }, ignore_index=True)
    return total_yearly_exp_df

def app_of_fund(project_cost_df, params_dict):
    
    app_of_fund_df = project_cost_df.drop(index=project_cost_df[project_cost_df['Items'].isin(['Working Capital', 'Total'])].index)
    app_of_fund_df.rename(columns={'Amount (₹)':'Rate'}, inplace=True)

    app_of_fund_df['Subsidy %'] = params_dict['subsidy']
    app_of_fund_df['No'] = 1
    app_of_fund_df['Amount (₹)'] = app_of_fund_df['Rate']*app_of_fund_df['No']

    app_of_fund_df = app_of_fund_df.append([{
            'Sl No.': '',
            'Items' : 'Total Investment',
            'Subsidy %': '',
            'No': '',
            'Rate': '',
            'Amount (₹)': app_of_fund_df['Amount (₹)'].sum()
                  },
                    {
            'Sl No.': '',
            'Items' : 'Total Subsidy',
            'Subsidy %': '',
            'No': '',
            'Rate': '',
            'Amount (₹)': sum(app_of_fund_df['Subsidy %']*app_of_fund_df['Amount (₹)'])
                    }]
                , ignore_index=True)

    app_of_fund_df = app_of_fund_df.append({
            'Sl No.': '',
            'Items' : 'Net Investment',
            'Subsidy %': '',
            'No': '',
            'Rate': '',
            'Amount (₹)': app_of_fund_df['Amount (₹)'][app_of_fund_df['Items'].isin(['Total Investment'])].values[0]
                        - app_of_fund_df['Amount (₹)'][app_of_fund_df['Items'].isin(['Total Subsidy'])].values[0]
                  }
                , ignore_index=True)
    return app_of_fund_df

def means_of_finance(params_dict):
    means_of_finance_df = pd.DataFrame(
                                        [
                                            [1, 'Term Loan', params_dict['term_loan']],
                                            [2, 'Working Capital Loan', params_dict['working_capital_loan']],
                                            [3, 'Total Loan', params_dict['total_bank_loan']],
                                            [4, 'Term Loan Contribution', params_dict['term_loan_contribution']],
                                            [5, 'Working Loan Contribution', params_dict['working_loan_contribution']]
                                        ],
                                        columns=['Sl No', 'Items', 'Amount (₹)']
                                        )
    return means_of_finance_df

def get_monthly_payment(p, r, t):
    return round((r/12) * (1/(1-(1+r/12)**(-t)))*p,2)

def get_repayment_schedule(params_dict):
    periods = params_dict['years']*12
    principle = params_dict['term_loan']
        
    params_dict['monthly_repayment_amt'] = get_monthly_payment(p=principle, r=params_dict['interest'], t=periods)
    
    df = pd.DataFrame(
                        columns=['Year', 'Month', 'Installment', 'Outstanding at the Beginning', 'Principle Repayment', 'Interest', 'Amount Paid', 'Outstanding at the End']
                        )
    
    for i in range(1, params_dict['years']*12+1):
        temp_dict = {}
        date = (dt.now() + pd.DateOffset(months=i))
        temp_dict['Year'] = date.year - dt.now().year+1 if date.month >= 4 else date.year-dt.now().year
        temp_dict['Month'] = date.strftime('%b %Y')
        temp_dict['Installment'] = i
        temp_dict['Outstanding at the Beginning'] = round(principle, 2)
        temp_dict['Interest'] = round(principle*params_dict['interest']/12, 2)
        temp_dict['Principle Repayment'] = round((params_dict['monthly_repayment_amt'] - temp_dict['Interest']), 2)
        temp_dict['Amount Paid'] = params_dict['monthly_repayment_amt']
        principle -= temp_dict['Principle Repayment']
        temp_dict['Outstanding at the End'] = round(principle, 2)
        
        df = df.append(temp_dict, ignore_index=True)
        
    grouped_df = (df[['Year', 'Principle Repayment', 'Interest', 'Outstanding at the End']]
                 .groupby(['Year'])
                 .agg({'Principle Repayment':'sum', 'Interest':'sum', 'Outstanding at the End':'min'})
                 .loc[:5])
    
    interest_on_tl = grouped_df['Interest'].to_list()
    loan_principle = grouped_df['Principle Repayment'].to_list()
    term_loan_list = grouped_df['Outstanding at the End'].to_list()
        
    params_dict['interest_on_tl'] = interest_on_tl     
    params_dict['loan_principle'] = loan_principle
    params_dict['term_loan_list'] = term_loan_list

    return df, params_dict

def depreciation_func(params_dict):    
    fixed_asset = round(params_dict['term_loan_contribution'] + params_dict['monthly_repayment_amt'], 2)
    total_asset = round(fixed_asset + params_dict['term_loan'], 2)

    depreciation_df = pd.DataFrame(columns=['Particulars', 'Rate'] + create_date_cols(params_dict['years']))
    for key, value in params_dict['tl'].rate_dict.items():

        for i in range(params_dict['years']):
            if i == 0:
                row1 = [round(params_dict['tl'].dict_info()[key], 2)]
                row2 = [round((row1[0]*value*params_dict['months'])/1200, 2)]
                row3 = [round(row1[0]-row2[0], 2)]
            else:
                row1.append(round(row3[i-1], 2))
                row2.append(round((row1[i]*value)/100, 2))
                row3.append(round(row1[i]-row2[i], 2))
                
        depreciation_df.loc[depreciation_df.shape[0]] = [key, value] + row1
        depreciation_df.loc[depreciation_df.shape[0]] = ['Less Depreciation', np.nan] + row2
        depreciation_df.loc[depreciation_df.shape[0]] = ['Written Down Value', np.nan] + row3


    depreciation = depreciation_df.loc[depreciation_df['Particulars']=='Less Depreciation'].iloc[:, 2:].sum().to_list()
    twdv = []
    for i in range(params_dict['years']):
        if i==0:
            twdv.append(total_asset - depreciation[0])
        else:
            twdv.append(twdv[i-1] - depreciation[i])

    depreciation_df.loc[depreciation_df.shape[0]] = ['Total Less Depreciation', np.nan] + depreciation
    depreciation_df.loc[depreciation_df.shape[0]] = ['Total Written Down Value', np.nan] + twdv
    depreciation_df = depreciation_df.apply(lambda x: x.replace(params_dict['tl'].naming_dict))
    
    params_dict['fixed_asset'] = fixed_asset
    params_dict['twdv'] = twdv
    params_dict['depreciation'] = depreciation
    
    return depreciation_df, params_dict

def profitability_statement(params_dict):
    revenue_list = [params_dict['revenue']] + create_row(params_dict['revenue12'], params_dict['multiplier'], years=params_dict['years'])[1:]
    closing_stock = create_row(params_dict['stock_in_hand'], params_dict['multiplier'], years=params_dict['years'])
    total1 = sum_list(revenue_list, closing_stock)
    
    opening_stock = [0] + closing_stock[:params_dict['years']-1]
    
    exp_dict1 = {}
    for item in params_dict['wc'].exp_type1:
        if item in params_dict['wc'].dict_info().keys():
            item_value = params_dict['wc'].dict_info()[item]
            exp_dict1[item] = [item_value * params_dict['months']] + create_row(item_value*12, params_dict['multiplier'], params_dict['years'])[1:]
        else:
            pass

    exp1_sum = sum_list(*list(exp_dict1.values()))
    total2 = sum_list(opening_stock, exp1_sum)
    
    gross_profit = subtract_list(total1, total2)
    
    exp_dict2 = {}
    for item in params_dict['wc'].exp_type2:
        if item in params_dict['wc'].dict_info().keys():
            item_value = params_dict['wc'].dict_info()[item]
            exp_dict2[item] = [item_value * params_dict['months']] + create_row(item_value*12, params_dict['multiplier'], params_dict['years'])[1:]
        else:
            pass
    
    total3 = sum_list(*list(exp_dict2.values()))
    
    interest_on_wc = [params_dict['working_capital_loan']*params_dict['interest']*params_dict['months']/12] + create_row(params_dict['working_capital_loan'] * params_dict['interest'], multiplier=1, years=params_dict['years']-1)
    total4 = sum_list(total3, params_dict['depreciation'], params_dict['interest_on_tl'], interest_on_wc)
    
    profit_before_tax = subtract_list(gross_profit, total4)
    income_tax_list = [round(ele*params_dict['income_tax'], 2) for ele in profit_before_tax]
    profit_after_tax = subtract_list(profit_before_tax, income_tax_list)
    
    expense_list = sum_list(total2, total3)
    
    profitability_statement_df = pd.DataFrame(
                ([
                    [],
                    revenue_list,
                    [],
                    closing_stock,
                    total1,
                    [],
                    opening_stock] 
                    + list(exp_dict1.values()) +
                    [total2,
                    gross_profit,
                    []]
                    + list(exp_dict2.values()) +
                    [total3,
                    params_dict['depreciation'],
                    params_dict['interest_on_tl'],
                    interest_on_wc,
                    total4,
                    profit_before_tax,
                    income_tax_list,
                    profit_after_tax
                ]),
                index = (['Revenue from Operation', params_dict['product'], 'Add:', 'Closing Stock', 'Total', 'Less:', 'Opening Stock']
                         + list(exp_dict1.keys()) + ['Total', 'Gross Profit', 'Less:'] + list(exp_dict2.keys()) + 
                         ['Total', 'Depreciation', 'Interest on TL', 'Interest on WC', 'Total', 'Profit before Tax', 'Income Tax', 'Profit After Tax']),
                columns= create_date_cols(params_dict['years'])
                )

    profitability_statement_df.index = [(params_dict['tl'].naming_dict | params_dict['wc'].naming_dict)[key] if key in (params_dict['tl'].naming_dict | params_dict['wc'].naming_dict).keys() else key for key in profitability_statement_df.index]
    
    params_dict['profit_before_tax'] = profit_before_tax
    params_dict['profit_after_tax'] = profit_after_tax
    params_dict['gross_profit'] = gross_profit
    params_dict['closing_stock'] = closing_stock
    params_dict['interest_on_wc'] = interest_on_wc
    params_dict['income_tax_list'] = income_tax_list
    params_dict['revenue_list'] = revenue_list
    params_dict['total3'] = total3
    params_dict['expense_list'] = expense_list
    
    return profitability_statement_df, params_dict

def cash_flow(params_dict):
    capital_list = [params_dict['term_loan_contribution'], params_dict['working_loan_contribution']] + create_zeroes(params_dict['years']-1)
    subsidy_list = [params_dict['subsidy']] + create_row(params_dict['subsidy'], multiplier=1, years=params_dict['years'])
    
    term_loan_list_cf = [params_dict['term_loan']] + create_zeroes(params_dict['years'])
    profit_before_tax6 = [0.00] + sum_list(params_dict['profit_before_tax'], params_dict['interest_on_tl'], params_dict['interest_on_wc'])
    
    inc_in_wc_loan = [0.00, params_dict['working_capital_loan']] + create_zeroes(params_dict['years']-1)
    depreciation6 = [0.00] + params_dict['depreciation']
    
    inc_in_curr_liability = create_zeroes(params_dict['years']+1)
    total_cash_inflow = sum_list(capital_list, subsidy_list, term_loan_list_cf, profit_before_tax6, inc_in_wc_loan, depreciation6, inc_in_curr_liability)

    fixed_asset_list = [total_cash_inflow[0]] + create_zeroes(params_dict['years'])
    inc_in_curr_asset = [0.00, params_dict['stock_in_hand']] + [round(ele/10, 2) for ele in params_dict['closing_stock'][:params_dict['years']-1]]
    
    interest_on_tl6 = [0.00] + params_dict['interest_on_tl']
    interest_on_wc6 = [0.00] + params_dict['interest_on_wc']
    
    income_tax6 = [0.00] + params_dict['income_tax_list']
    dec_in_tl6 = [0.00] + params_dict['loan_principle']
    
    divident_on_equity = create_zeroes(params_dict['years']+1)
    total_cash_outflow = sum_list(fixed_asset_list, inc_in_curr_asset, interest_on_tl6, interest_on_wc6, income_tax6, dec_in_tl6, divident_on_equity)
    net_cash_flow = subtract_list(total_cash_inflow, total_cash_outflow)
    
    opening_balance = [sum(net_cash_flow[:i]) for i in range(len(net_cash_flow))]
    closing_balance = [sum(net_cash_flow[:i]) for i in range(1, len(net_cash_flow)+1)]
    
    cash_flow_statement_df = pd.DataFrame(
                                    [
                                        [],
                                        capital_list,
                                        subsidy_list,
                                        term_loan_list_cf,
                                        profit_before_tax6,
                                        inc_in_wc_loan,
                                        depreciation6,
                                        inc_in_curr_liability,
                                        total_cash_inflow,
                                        [],
                                        fixed_asset_list,
                                        inc_in_curr_asset,
                                        interest_on_tl6,
                                        interest_on_wc6,
                                        income_tax6,
                                        dec_in_tl6,
                                        divident_on_equity,
                                        total_cash_outflow,
                                        opening_balance,
                                        net_cash_flow,
                                        closing_balance
                                    ],
                                    index=['Cash Inflow', 'Capital', 'Subsidy', 'Term Loan', 'Profit before Tax with Interest', 'Increase in WC Loan', 'Depreciation', 'Increase in Current Liability', 'Total Cash Inflow', 'Cash Outflow', 'Fixed Assets',
                                          'Increase in Current Asset', 'Interest on TL', 'Interest on WC', 'Income Tax', 'Decrease in Term Loan', 'Divident on Equity', 'Total Cash Outflow', 'Opening Balance', ' Net Cashflow', 'Closing Balance'],
                                    
                                    columns=['Pre Operative Period'] + create_date_cols(params_dict['years'])
                                    )
    
    params_dict['profit_before_tax6'] = profit_before_tax6
    params_dict['closing_balance'] = closing_balance
    params_dict['fixed_asset_list'] = fixed_asset_list
    
    return cash_flow_statement_df, params_dict

def balance_sheet(params_dict):
    
    capital_list_bs = [params_dict['term_loan_contribution']] + [params_dict['promoter_contrbution'] for i in range(params_dict['years'])]
    reserve_surplus = [0.00] + list(np.cumsum(params_dict['profit_after_tax']))    
    term_loan_list_bs = [params_dict['term_loan']] + params_dict['term_loan_list']
    working_cap_loan_list = [0.00] + [params_dict['working_capital_loan'] for i in range(params_dict['years'])]
    account_payable = create_zeroes(params_dict['years']+1)
    total_liability = sum_list(capital_list_bs, reserve_surplus, term_loan_list_bs, working_cap_loan_list, account_payable)
    
    fixed_assets_bs = [params_dict['fixed_asset_list'][0]] + params_dict['twdv']
    inventory = [0.00] + params_dict['closing_stock']
    trade_receivables = create_zeroes(params_dict['years']+1)
    cash_n_equivalence = params_dict['closing_balance']
    total_asset_list = sum_list(fixed_assets_bs, inventory, trade_receivables, cash_n_equivalence)
    
    balance_sheet_df = pd.DataFrame(
                                [
                                    [],
                                    [],
                                    capital_list_bs,
                                    reserve_surplus,
                                    [],
                                    term_loan_list_bs,
                                    [],
                                    working_cap_loan_list,
                                    account_payable,
                                    total_liability,
                                    [],
                                    [],
                                    fixed_assets_bs,
                                    [],
                                    inventory,
                                    trade_receivables,
                                    cash_n_equivalence,
                                    total_asset_list
                                ],
                                index=['Liability', 'A. Share Holders Funds', 'Capital', 'Reserve & Surplus', 'B. Non Current Liabilities', 'Term Loan', 'C. Current Liabilities', 'Working Capital Loan', 'Account Payable', 'Total Liability',
                                       'Asset', 'A. Non Current Assets', 'Fixed Assets', 'B. Current Assets', 'Inventory', 'Trade Receivables', 'Cash and Cash Equivalence', 'Total Asset'],
                                columns=['Pre Operative Period'] + create_date_cols(params_dict['years'])
                                )
    
    params_dict['inventory'] = inventory
    params_dict['cash_n_equivalence'] = cash_n_equivalence
    params_dict['reserve_surplus'] = reserve_surplus
    params_dict['working_cap_loan_list'] = working_cap_loan_list
    params_dict['capital_list_bs'] = capital_list_bs
    params_dict['term_loan_list_bs'] = term_loan_list_bs

    return balance_sheet_df, params_dict

def dscr_func(params_dict):
    total1 = sum_list(params_dict['profit_after_tax'], params_dict['depreciation'], params_dict['interest_on_tl'])
    total2 = sum_list(params_dict['loan_principle'], params_dict['interest_on_tl'])
    
    dscr = divide_list(total1, total2)
    
    dscr_df = pd.DataFrame(
                        [
                            [],
                            params_dict['profit_after_tax'],
                            params_dict['depreciation'],
                            params_dict['interest_on_tl'],
                            total1,
                            [],
                            params_dict['loan_principle'],
                            params_dict['interest_on_tl'],
                            total2,
                            dscr
                        ],
                        index=['Receipts', 'a). Net Profit', 'b). Depreciation', 'c). Interest on Term Loan', 'Total',
                              'Repayments', 'a). Loan Principle', 'b). Interest on Termloan', 'Total', 'DSCR'],
                        columns = create_date_cols(params_dict['years'])
                        )
    params_dict['dscr'] = dscr
    #dscr_df.index.name = 'Particulars'
    return dscr_df, params_dict

def project_feasibilty(params_dict):
    expense_list1 = subtract_list(params_dict['revenue_list'], params_dict['gross_profit'])
    expense_list2 = subtract_list(params_dict['revenue_list'], params_dict['profit_after_tax'])
    
    current_ratio = divide_list(sum_list(params_dict['inventory'][1:], params_dict['cash_n_equivalence'][1:]), params_dict['working_cap_loan_list'][1:])
    quick_ratio = divide_list(params_dict['cash_n_equivalence'][1:], params_dict['working_cap_loan_list'][1:])
    
    ebit = subtract_list(params_dict['gross_profit'], params_dict['total3'])
    interest_exp = sum_list(params_dict['interest_on_tl'], params_dict['interest_on_wc'])
    interest_cov_ratio = divide_list(ebit, interest_exp)
    
    debt_equity_ratio = divide_list(sum_list(params_dict['term_loan_list_bs'][1:], params_dict['working_cap_loan_list'][1:]), sum_list(params_dict['reserve_surplus'][1:], params_dict['capital_list_bs']))
    tol_tnw = divide_list(sum_list(params_dict['term_loan_list_bs'][1:], params_dict['working_cap_loan_list'][1:]), sum_list(params_dict['capital_list_bs'][1:], params_dict['reserve_surplus'][1:]))
    
    gross_profit_perc = [f'{val} %' for val in calc_ratio(expense_list1, params_dict['revenue_list'])]
    net_profit_perc = [f'{val} %' for val in calc_ratio(expense_list2, params_dict['revenue_list'])]
    
    
    ebt = subtract_list(subtract_list(params_dict['gross_profit'], params_dict['total3']), params_dict['depreciation'])
    capital_employed = sum_list(params_dict['term_loan_list'], params_dict['working_cap_loan_list'][1:], params_dict['capital_list_bs'][1:], params_dict['reserve_surplus'][1:])
    roce = divide_list(ebt, capital_employed)
    
    project_feasibility_df = (pd.DataFrame(
                                        [
                                            current_ratio,
                                            quick_ratio,
                                            interest_cov_ratio,
                                            debt_equity_ratio,
                                            tol_tnw,
                                            params_dict['dscr'],
                                            gross_profit_perc,
                                            net_profit_perc,
                                            roce
                                        ],
                                        index=['Current Ratio', 'Quick Ratio', 'Interest Coverage Ratio', 'Debt Equity ratio', 'TOL/TNW', 'DSCR',
                                              'Gross Profit Sales %', 'Net Profit Sales %', 'Return on Capital Employed'],
                                        columns=[f'Year {i}' for i in range(1, params_dict['years']+1)]
                                        ))
    params_dict['expense_list2'] = expense_list2
    params_dict['current_ratio'] = current_ratio
                                                                                
    return project_feasibility_df, params_dict

def plot_line(project_feasibility_df):
    fig, [ax1, ax2] = plt.subplots(1, 2, figsize=(15, 5))

    plot1, = ax1.plot(project_feasibility_df.loc['Net Profit Sales %'].apply(lambda x: float(x.replace('%', '').strip())), '--go', linewidth=3, c='g')
    plot2, = ax2.plot(project_feasibility_df.loc['Quick Ratio'], '--bo', linewidth=3, c='b')

    ax1.set_ylabel('%')
    ax2.set_ylabel('%')

    plot1_data = plot1.get_ydata()
    plot2_data = plot2.get_ydata()

    ymax1 = plot1_data.max() + plot1_data.mean() if plot1_data.max() <= 90 else 100
    ymax2 = plot2_data.max() + plot2_data.mean() if plot2_data.max() <= 90 else 100

    ax1.set_ylim(ymin=0, ymax=ymax1)
    ax2.set_ylim(ymin=0, ymax=ymax2)
    
    for i, (y1, y2) in enumerate(zip(plot1_data, plot2_data)):
        ax1.annotate(project_feasibility_df.loc['Net Profit Sales %'][i], (i, y1), xytext=(i, y1+2))
        ax2.annotate(project_feasibility_df.loc['Quick Ratio'][i], (i, y2), xytext=(i, y2+2))

    ax1.set_title('Net profit Sales %')
    ax2.set_title('Quick Ratio')

    render_plot(plt)
    
def plot_bar(params_dict):
    revenue_list_new = sum_list(params_dict['revenue_list'], params_dict['closing_stock'])
    labels = [f'Year {i}' for i in range(1, params_dict['years']+1)]

    x = np.arange(params_dict['years'])  # the label locations
    width = 0.35  # the width of the bars

    fig, ax = plt.subplots(figsize=(15,10))
    rects1 = ax.bar(x - width/2, revenue_list_new, width, label='Revenue')
    rects2 = ax.bar(x + width/2, params_dict['expense_list'], width, label='Expense')

    # Add some text for labels, title and custom x-axis tick labels, etc.
    ax.set_ylabel('In Lakhs (₹)')
    ax.set_title('Revenue v/s Expense')
    ax.set_xticks(x, labels)
    ax.legend()

    ax.set_yticklabels([ytick/100000 for ytick in ax.get_yticks()])

    ax.bar_label(rects1, padding=3, labels=[f'{bar1.get_height()/100000:.1f}' for bar1 in rects1])
    ax.bar_label(rects2, padding=3, labels=[f'{bar2.get_height()/100000:.1f}' for bar2 in rects2])

    fig.tight_layout()
    render_plot(plt)

def plot_pie(total_yearly_exp_df):
    pie_df = total_yearly_exp_df.drop(index=[total_yearly_exp_df.shape[0]-1], columns=['Sl No.'])
    plt.figure(figsize=(10, 10))
    plt.pie(x=pie_df['Amount (₹)'],
           labels=pie_df['Items'],
           autopct='%.2f%%',
           explode=[0.1 if pie_df['Amount (₹)'].idxmax()==idx else 0 for idx in pie_df.index],
           shadow=True,
           textprops={'fontsize': 12}
           )
    plt.title('Expense Splitup')
    render_plot(plt)

def generate_report(working_capital_loan, marginal_money=0.1, years=5, stock_in_hand_perc=2/3, interest=0.11, subsidy=0.00, income_tax=0.00, product='Sales from Fish', quantity=200, rate=2428.54, unit='Kg', no_of_employment=5, **kwargs):
    params_tl = {key:value for key, value in kwargs.items() if key in TermLoan.naming_dict}
    params_wc = {key:value for key, value in kwargs.items() if key in WCLoan.naming_dict}
    
    params_dict = {'working_capital_loan':working_capital_loan, 'marginal_money':marginal_money, 'years':years,
                   'stock_in_hand_perc':stock_in_hand_perc, 'interest':interest, 'subsidy':subsidy, 'income_tax':income_tax,
                   'product':product, 'quantity':quantity, 'rate':rate, 'unit':unit, 'no_of_employment':no_of_employment}
    
    params_dict['tl'] = TermLoan(**params_tl)
    params_dict['wc'] = WCLoan(**params_wc)
    
    params_dict['project_cost'] = params_dict['tl'].project_cost()
    params_dict['multiplier'] = 1.1 #Assuming 
    
    project_at_a_glance_df, params_dict = project_at_a_glance(params_dict=params_dict)
    
    project_cost_df = project_cost_func(params_dict=params_dict)
    
    working_capital__computation_df = working_cap_comp(params_dict=params_dict)

    annual_revenue_df, params_dict = annual_revenue(params_dict=params_dict)

    total_yearly_exp_df = total_yearly_exp(params_dict=params_dict)

    app_of_fund_df = app_of_fund(project_cost_df=project_cost_df, params_dict=params_dict)

    means_of_finance_df = means_of_finance(params_dict=params_dict)

    repayment_schedule_df, params_dict = get_repayment_schedule(params_dict=params_dict)

    depreciation_df, params_dict = depreciation_func(params_dict=params_dict)

    profitability_statement_df, params_dict = profitability_statement(params_dict=params_dict)

    cash_flow_statement_df, params_dict = cash_flow(params_dict=params_dict)

    balance_sheet_df, params_dict = balance_sheet(params_dict=params_dict)

    dscr_df, params_dict = dscr_func(params_dict=params_dict)

    project_feasibility_df, params_dict = project_feasibilty(params_dict=params_dict)

    render_dataframe(project_at_a_glance_df).style.hide_columns().format(precision=2).set_caption('Project at a Glance')
    render_dataframe(project_feasibility_df).style.format(precision=2).set_caption('Project Feasibility Ratio')
    plot_line(project_feasibility_df=project_feasibility_df)
    plot_bar(params_dict)
    plot_pie(total_yearly_exp_df=total_yearly_exp_df)
    render_dataframe(project_cost_df).style.hide_index().format(precision=2).set_caption('Project Cost')
    render_dataframe(working_capital__computation_df).style.hide_index().format(precision=2).set_caption('Working Capital ComputationSl.')
    render_dataframe(annual_revenue_df).style.hide_index().format(na_rep='', precision=2).set_caption('Annual Sales / RevenueSl.')
    render_dataframe(total_yearly_exp_df).style.hide_index().format(precision=2).set_caption('Total Yearly Expense')
    render_dataframe(app_of_fund_df).style.hide_index().format(precision=2).set_caption('Application of Fund')
    render_dataframe(means_of_finance_df).style.hide_index().format(precision=2).set_caption('Means of Finance')
    render_dataframe(profitability_statement_df).style.format(na_rep='', precision=2).set_caption('Profitability Statement')
    render_dataframe(cash_flow_statement_df).style.format(na_rep='', precision=2).set_caption('Cash flow statement')
    render_dataframe(balance_sheet_df).style.format(na_rep='', precision=2).set_caption('Balance sheet')
    render_dataframe(repayment_schedule_df).style.hide_index().format(precision=2).set_caption('Repayment of Term loan')
    render_dataframe(dscr_df.style).format(na_rep='', precision=2).set_caption('Debt Service Coverage Ratio')
    render_dataframe(depreciation_df).style.format(na_rep='', precision=2).hide_index().set_caption('Depreciation')

if __name__ == "__main__":
    kwargs = json.loads(sys.argv[1])
    # generate_report(working_capital_loan=working_capital_loan, marginal_money=0.25, stock_in_hand_perc=0.7, product='Sales from Soap', rate=53.52, quantity=15000, unit='Units', income_tax=0.3,  **kwargs)

    print("test")
#working_capital_loan and kwargs should be the input:
#working_capital_loan = 275000.00
#kwargs = {
    #'land':100000.00, 'shed':200000.00, 'machine':300000.00, 'computer':400000.00, 'furniture':500000.00, 'electricity':600000.00, 'storage':700000.00, 'vehicle':800000.00, 'software':900000.00, 'other_exp':1000000.00,
    #'rent':10000.00, 'salary':20000.00, 'consumables':30000.00, 'electric_water':50000.00, 'stationary':40000.00, 'repair':60000.00, 'transportation':70000.00, 'tele_internet':80000.00, 'market_ad':90000.00, 'misc':100000.00
            #}




