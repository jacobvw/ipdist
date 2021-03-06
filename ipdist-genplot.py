#!/usr/bin/python

import sys
import subprocess
import os

def normalise(min, max, value):
        return ((value - min) / float((max - min)))


# Ensure a data directory was supplied
if len(sys.argv) != 2:
	print("Usage: python ipdist-genplot data-directory")
	sys.exit()

dir = sys.argv[1]
dataFiles = []

# Stats
total_skew_src = [0, 0, 0, 0]
total_skew_dst = [0, 0, 0, 0]

# Get all data/stats files contained within the directory
for file in os.listdir(dir):
	if file.endswith(".data"):
		dataFiles.append(file)

# sort the datafiles list so they are read in the correct order
dataFiles.sort()

# Every datafile should have a corresponding stats file
# Iterate over every dataFile
for i in range(len(dataFiles)):
	dataFile = dataFiles[i]
	filename,extension = dataFiles[i].split(".")
	statsFile = filename + ".stats"
	tick = filename.split("-")
	tick = tick[1]

	# Open the current stats file
	lines = []
	with open(dir + "/" + statsFile, "r") as tmp:
		lines = tmp.readlines()
	# increment the total skew counters
	for x in range(4):
		total_skew_src[x] = 0.0
		total_skew_dst[x] = 0.0
		total_skew_src[x] += float(lines[(4*x)+1].split()[6])
		total_skew_dst[x] += float(lines[(4*x)+2].split()[6])


	# Create/append to timeseries stats file
	# the file needs to be created on the first pass
	if i == 0:
		tmp = open(dir + "/ipdist-timeseries-skewness.stats", "w")
		tmp.write("timestamp\tsrc1\t\tdst1\t\tsrc2\t\tdst2\t\tsrc3\t\tdst3\t\tsrc4\t\tdst4\n")
	else:
		tmp = open(dir + "/ipdist-timeseries-skewness.stats", "a")
	tmp.write(tick)
	for x in range(4):
		#tmp.write("\t" + str(total_skew_src[x]/(i+1)) + "\t" + str(total_skew_dst[x]/(i+1)))
		tmp.write("\t" + str(total_skew_src[x]) + "\t" + str(total_skew_dst[x]))
	tmp.write("\n")
	tmp.close()


	# open data file to read from and count all occurances
	with open(dir + "/" + dataFile, "r") as tmp:
		lines = tmp.readlines()
	tmp.close()
	# create arrays to hold counts
	count_src = [0] * 4
	count_dst = [0] * 4
	# count all octet counts in the current data file
	for x in range(4):
		count_src[x] = [0] * 256
		count_dst[x] = [0] * 256
	# count all occurances
	for x in range(256):
		for k in range(4):
			count_src[k][int(lines[x+2].split()[(k*4)+2])] = int(lines[x+2].split()[(k*4)+3])
			count_dst[k][int(lines[x+2].split()[(k*4)+4])] = int(lines[x+2].split()[(k*4)+5])


	# create tmp file for cdf plots
	with open(dir + "/ipdist-" + tick + ".tmp", "w") as tmp:
		for x in range(4):
			total_src = 0
			total_dst = 0
			min_src = 0
			min_dst = 0
			max_src = 0
			max_dst = 0

			# work out min and max needed to normalise the data for CDF
			for i in range(256):
				curr_src = count_src[x][i]
				curr_dst = count_dst[x][i]
				if curr_src < min_src or i == 0:
					min_src = 0
				if curr_dst < min_dst or i == 0:
					min_dst = 0
				# cumulative count
				max_src = max_src + curr_src
				max_dst = max_dst + curr_dst

			for i in range(256):
				total_src = total_src + count_src[x][i]
				total_dst = total_dst + count_dst[x][i]
				tmp.write(str(normalise(min_src, max_src, total_src)) + "\t" + str(i) + "\t" + str(normalise(min_dst, max_dst, total_dst)) + "\t" + str(i) + "\n")
			tmp.write("\n\n")


	# create interval plots
	for x in range(4):
		plot = subprocess.Popen(['gnuplot -persistent','-p'],
					shell=True,
					stdin=subprocess.PIPE,)

		# Source
		plot.stdin.write("set term pngcairo enhanced size 960,640\n")
		plot.stdin.write("set output '" + dir + "/" + filename + "-octet" + str(x+1) + "-source.png'\n")
		plot.stdin.write("set title 'Source IP Distribution octet " + str(x+1) + " time " + tick + "'\n")
		plot.stdin.write("set xrange[0:255]\n")
		plot.stdin.write("set xlabel 'Prefix'\n")
		plot.stdin.write("set ylabel 'Hits'\n")
		plot.stdin.write("set xtics 0,10,255 rotate by 60 right\n")
		plot.stdin.write("set yrange [0:*]\n")
		plot.stdin.write("plot '" + dir + "/" + dataFile + "' using " + str((x*4)+3) + ":" + str((x*4)+4) + " index 0 title 'Source octet " + str(x+1) + "' smooth unique with boxes\n")
		plot.stdin.flush()

		# Destination
		plot.stdin.write("set term pngcairo enhanced size 960,640\n")
                plot.stdin.write("set output '" + dir + "/" + filename + "-octet" + str(x+1) + "-destination.png'\n")
                plot.stdin.write("set title 'Destination IP Distribution octet " + str(x+1) + " time " + tick + "'\n")
                plot.stdin.write("set xrange[0:255]\n")
                plot.stdin.write("set xlabel 'Prefix'\n")
                plot.stdin.write("set ylabel 'Hits'\n")
                plot.stdin.write("set xtics 0,10,255 rotate by 60 right\n")
		plot.stdin.write("set yrange [0:*]\n")
		plot.stdin.write("plot '" + dir + "/" + dataFile + "' using " + str((x*4)+5) + ":" + str((x*4)+6) + " index 0 title 'Destination octet " + str(x+1) + "' smooth unique with boxes\n")
		plot.stdin.flush()

		# CDF
		plot.stdin.write("set term pngcairo enhanced size 960,640\n")
                plot.stdin.write("set output '" + dir + "/" + filename + "-octet" + str(x+1) + "-cdf.png'\n")
		plot.stdin.write("set title 'CDF distribution octet " + str(x+1) + " time " + tick + "'\n")
		plot.stdin.write("set ylabel 'Cumulative %'\n")
		plot.stdin.write("set yrange[-0.1:1.1]\n")
                plot.stdin.write("set xlabel 'Prefix'\n")
		plot.stdin.write("set xtics rotate by 60 right\n")
		plot.stdin.write("set key right bottom\n")
                plot.stdin.write("plot '" + dir + "/ipdist-" + tick + ".tmp' using 2:1 index " + str(x) + " with lines title 'Source octet " + str(x+1) + "',")
                plot.stdin.write("'" + dir + "/ipdist-" + tick + ".tmp' using 4:3 index " + str(x) + " with lines title 'Destination octet " + str(x+1) + "'\n")
		plot.stdin.flush()

		# Zipf distribution
		plot.stdin.write("set term pngcairo enhanced size 960,640\n")
                plot.stdin.write("set output '" + dir + "/" + filename + "-octet" + str(x+1) + "-zipf.png'\n")
		plot.stdin.write("set title 'Zipf distribution octet " + str(x+1) + " time " + tick + "'\n")
		plot.stdin.write("set xlabel 'Rank'\n")
		plot.stdin.write("set xrange [1:255]\n")
		#plot.stdin.write("set xtics 1,10,255\n")
		plot.stdin.write("set ylabel 'Frequency (log 10)'\n")
		plot.stdin.write("set yrange [1:*]\n")
		plot.stdin.write("unset yrange\n")
		plot.stdin.write("unset xtics\n")
		plot.stdin.write("set xtics\n")
		plot.stdin.write("set logscale xy 10\n")
		plot.stdin.write("set key top right\n")
		plot.stdin.write("plot '" + dir + "/" + dataFile + "' using 2:" + str((x*4)+4) + " index 0 title 'Source octet " + str(x+1) + "',")
		plot.stdin.write("'' using 2:" + str((x*4)+6) + " index 0 title 'Destination octet " + str(x+1) + "'\n")
		plot.stdin.flush()

		plot.communicate()


# Generate plots for the timeseries data captured over the entire trace
for i in range(4):
	plot = subprocess.Popen(['gnuplot -persistent','-p'],
                                shell=True,
                                stdin=subprocess.PIPE,)
	plot.stdin.write("set term pngcairo size 960,640\n")
	plot.stdin.write("set output '" + dir + "/ipdist-octet" + str(i+1) + "-source.png'\n")
	plot.stdin.write("set title 'CDF source octet " + str(i+1) + "'\n")
	plot.stdin.write("set xlabel 'Prefix'\n")
	plot.stdin.write("set ylabel 'Cumulative %'\n")
	plot.stdin.write("set yrange [-0.1:1.1]\n")
	plot.stdin.write("set xrange[0:255]\n")
	plot.stdin.write("set xtics 0,10,255 rotate by 60 right\n")
	plot.stdin.write("set key off\n")
	for x in range(0, len(dataFiles), 3):
                dataFile = dataFiles[x]
                filename,extension = dataFiles[x].split(".")
                tick = filename.split("-")
                tick = tick[1]

		if x == 0:
			plot.stdin.write("plot '" + dir + "/ipdist-" + tick + ".tmp' using 2:1 index " + str(i) + " title '" + tick + "' with lines,")
		else:
			plot.stdin.write(" '" + dir + "/ipdist-" + tick + ".tmp' using 2:1 index " + str(i) + " title '" + tick + "' with lines,")
	plot.stdin.write("\n")
	plot.stdin.flush();

	plot.stdin.write("set term pngcairo size 960,640\n")
        plot.stdin.write("set output '" + dir + "/ipdist-octet" + str(i+1) + "-destination.png'\n")
	plot.stdin.write("set title 'CDF destination octet " + str(i+1) + "'\n")
	plot.stdin.write("set xlabel 'Prefix'\n")
        plot.stdin.write("set ylabel 'Cumulative %'\n")
	plot.stdin.write("set yrange [-0.1:1.1]\n")
	plot.stdin.write("set xrange[0:255]\n")
	plot.stdin.write("set xtics 0,10,255 rotate by 60 right\n")
	plot.stdin.write("set key off\n")
	for x in range(0, len(dataFiles), 3):
		dataFile = dataFiles[x]
                filename,extension = dataFiles[x].split(".")
                tick = filename.split("-")
                tick = tick[1]

		if x == 0:
			plot.stdin.write("plot '" + dir + "/ipdist-" + tick + ".tmp' using 4:3 index " + str(i) + " title '" + tick + "' with lines,")
		else:
			plot.stdin.write(" '" + dir + "/ipdist-" + tick + ".tmp' using 4:3 index " + str(i) + " title '" + tick + "' with lines,")
		# print every 4th result to cdf
		x += 3
	plot.stdin.write("\n")
	plot.stdin.flush();

	plot.stdin.write("set term pngcairo size 960,640\n")
        plot.stdin.write("set output '" + dir + "/ipdist-octet" + str(i+1) + "-skew.png'\n")
	plot.stdin.write("set title 'Skew octet " + str(i+1) + "'\n")
	plot.stdin.write("set yrange[-1:1]\n")
	plot.stdin.write("set xlabel 'Time'\n")
	plot.stdin.write("set ylabel 'Skewness'\n")
	plot.stdin.write("set autoscale x\n")
	plot.stdin.write("set key top right\n")
	plot.stdin.write("unset xtics\n")
	plot.stdin.write("plot '" + dir + "/ipdist-timeseries-skewness.stats' using " + str((i*2)+2) + ":xtic(1) title 'Source' with lines,")
	plot.stdin.write("'' using " + str((i*2)+3) + ":xtic(1) title 'Destination' with lines\n")
	plot.stdin.flush()

	plot.communicate()

# cleanup all tmp files
# tmp files created for CDF plots
for x in range(len(dataFiles)):
	dataFile = dataFiles[x]
        filename,extension = dataFiles[x].split(".")
        tick = filename.split("-")
        tick = tick[1]

	os.remove(dir + "/ipdist-" + tick + ".tmp")
# skew file
os.remove(dir + "/ipdist-timeseries-skewness.stats")
