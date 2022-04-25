"""
This module generates dataset for different phases.

"""

import numpy as np
import scipy.stats as st
import matplotlib

matplotlib.rcParams['figure.figsize'] = (16.0, 12.0)
"""
https://github.com/Pandinosaurus/UsefulScripts/blob/master/fit-data-distribution_scipy.py
"""

def getTheBestData(beta, dataSize):
    data = np.random.exponential(scale=beta, size=dataSize)
    dist_names2 = ['norm', 'weibull_min', 'genextreme', 'gamma', 'expon', 'pearson3']
    dist_results = []
    params = {}
    for dist_name in dist_names2:
        dist = getattr(st, dist_name)
        param = dist.fit(data)

        params[dist_name] = param
        # Applying the Kolmogorov-Smirnov test
        D, p = st.kstest(data, dist_name, args=param)
        dist_results.append((dist_name, p))

    # select the best fitted distribution
    best_dist, best_p = (max(dist_results, key=lambda item: item[1]))
    # store the name of the best fit and its p value
    return data, best_dist, best_p, params[best_dist]

def getCIParams(data, phase):
    #https://aegis4048.github.io/comprehensive_confidence_intervals_for_python_developers#python_ci_mean
    alpha = 0.05                       # significance level = 5%
    df = len(data) - 1                  # degress of freedom = 20
    t = st.t.ppf(1 - alpha/2, df)   # t-critical value for 95% CI = 2.093
    s = np.std(data, ddof=1)            # sample standard deviation = 2.502
    n = len(data)
    #print("alpha = ", alpha, " df: ", df, " t: ", t, " s: ", s, " n: ", n)
    print("Generating dataset for " + phase + " phase...")
    lower = np.mean(data) - (t * s / np.sqrt(n))
    upper = np.mean(data) + (t * s / np.sqrt(n))
    return lower, upper

def getData(beta, dataSize, phase):
    dataIsGood = False
    data1 = None
    while(dataIsGood == False):
        data1, bdist, bP, bParams = getTheBestData(beta, dataSize)
        if str(bdist) == "expon" and bP >= 0.99: #0.95:
            dataIsGood = True
    if dataIsGood == True:
        xStart, xEnd = getCIParams(data1, phase)
    return data1, bdist, bP, bParams, xStart, xEnd

def setupDataset(dataset):
    tempATDD = dataset.copy()
    for x in tempATDD:
        tempParams = []
        if str(x) == "AverageTime":
            pass
        else:
            if tempATDD[x]["timeData"] is None:
                mt = tempATDD["AverageTime"]*tempATDD[x]["proportion"]
                data1, bdist, bP, bParams, xStart, xEnd = getData(mt, 2000, str(x))
                tempParams.append(xStart)
                tempParams.append(xEnd)
                tempDict = dict(timeData = data1, dist = bdist, pVal = bP, params = bParams, parameterX = tempParams)
                dataset[x].update(tempDict)
    return None