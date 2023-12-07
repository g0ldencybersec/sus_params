# sus_params Project

## Overview
The `sus_params` project, led by Gunnar Andrews and Jason Haddix, extends the HUNT dataset to include Hacktivity Disclosures up to 2023. The project's goal is to identify statistical correlations between certain vulnerabilities and specific route or parameter names, aiding application security testers in focusing their efforts effectively.

## Features

- Comprehensive analysis of Hacktivity Disclosures up to 2023
- Data from platforms like Bugcrowd Crowdstream up to 2023
- Data from all Bugcrowd submissions up until 2016
- Identification of high-risk routes and parameters based on historical data

## Getting Started

#Using GF Pattern Files

The project includes GF pattern files in JSON format to help identify vulnerabilities. Here's how to use them:

1. Ensure you have `gf` (Grep-Friendly) installed. If not, install it from [here](https://github.com/tomnomnom/gf).
2. Copy the JSON pattern files to your `gf` patterns directory. Typically, this would be `~/.gf`
3. `gf pattern-name` Replace `pattern-name` with the name of the pattern you want to use like `sqli.json`


