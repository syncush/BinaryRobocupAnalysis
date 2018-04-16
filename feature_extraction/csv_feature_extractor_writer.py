import sys
import csv
from os import walk
import extractor

def write_to_csv(dir_to_analyze_path, dst_csv_path, csv_file_name):
    binaryPaths = []
    for (dirpath, dirnames, filenames) in walk(dir_to_analyze_path):
        temp = [dirpath + x for x in filenames]
        binaryPaths.extend(temp)
    with open(dst_csv_path + csv_file_name + ".csv", 'wb') as out:
        csv_out = csv.writer(out)
        csv_out.writerow(['name', 'num'])
        for binaryPath in binaryPaths:
            analyzer = extractor.FeatureExtractor(binaryPath)
            for row in data:
                csv_out.writerow(row)
