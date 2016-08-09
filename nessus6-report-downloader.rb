#!/usr/bin/env ruby
#################################################################################################
#
# Original script can be found here: https://github.com/eelsivart/nessus-report-downloader
#  
# Script was extended for usage with command line options and to automaticly download files
# from a give number of the last days (now-x). 
# This is needed for the usage of the script with cronjobs.
#
#################################################################################################

require 'net/http'
require 'fileutils'
require 'io/console'
require 'date'
require 'json'
require 'openssl'
require 'optparse'
require 'date'

# This method will download the specified file type from specified reports
def report_download(http, headers, reports, reports_to_dl, filetypes_to_dl, chapters_to_dl, rpath, db_export_pw)
	begin
		puts "\nDownloading report(s). Please wait..."

		# if all reports are selected
		if reports_to_dl[0].eql?("all")
			reports_to_dl.clear
			# re-init array with all the scan ids
			reports["scans"].each do |scan|
				reports_to_dl.push(scan["id"].to_s)
			end	
		end
		
		# iterate through all the indexes and download the reports
		reports_to_dl.each do |rep|
			rep = rep.strip
			filetypes_to_dl.each do |ft|
			
				# export report
				puts "\n[+] Exporting scan report, scan id: " + rep + ", type: " + ft
				path = "/scans/" + rep + "/export"
				data = {'format' => ft, 'chapters' => chapters_to_dl, 'password' => db_export_pw}
				resp = http.post(path, data.to_json, headers)
				fileid = JSON.parse(resp.body)
			
				# check export status
				status_path = "/scans/" + rep + "/export/" + fileid["file"].to_s + "/status"
				loop do
					sleep(5)
					puts "[+] Checking export status..."
					status_resp = http.get(status_path, headers)
					status_result = JSON.parse(status_resp.body)
					break if status_result["status"] == "ready"
					puts "[-] Export not ready yet, checking again in 5 secs."
				end

				# download report
				puts "[+] Report ready for download..."
				dl_path = "/scans/" + rep + "/export/" + fileid["file"].to_s + "/download"
				dl_resp = http.get(dl_path, headers)

				# create final path/filename and write to file
				fname_temp = dl_resp.response["Content-Disposition"].split('"')
				fname = "#{rpath}/#{fname_temp[1]}"
					
				# write file
				open(fname, 'w') { |f|
  					f.puts dl_resp.body
  				}
  			
  				puts "[+] Downloading report to: #{fname}"
  			end
		end
		
	rescue StandardError => download_report_error
		puts "\n\nError downloading report: #{download_report_error}\n\n"
		exit
	end
end

# This method will return a list of all the reports on the server
def get_report_list(http, headers)
	begin
		# Try and do stuff
		path = "/scans"
		resp = http.get(path, headers)

		#puts "Number of reports found: #{reports.count}\n\n"

		results = JSON.parse(resp.body)

		printf("%-7s %-50s %-30s %-15s\n", "Scan ID", "Name", "Last Modified", "Status")
		printf("%-7s %-50s %-30s %-15s\n", "-------", "----", "-------------", "------")

		# print out all the reports
		results["scans"].each do |scan|
			printf("%-7s %-50s %-30s %-15s\n", scan["id"], scan["name"], DateTime.strptime(scan["last_modification_date"].to_s,'%s').strftime('%b %e, %Y %H:%M %Z'), scan["status"])
		end
		return results
		
	rescue StandardError => get_scanlist_error
		puts "\n\nError getting scan list: #{get_scanlist_error}\n\n"
		exit
	end
end

# return a list of all reports of the last x days
def get_report_list_lastdays(http, headers, days)
	begin
		# Try and do stuff
		path = "/scans"
		d=days.to_i
		now = Date.today
		sometimes = now - d
		puts sometimes
		t=sometimes.to_time.to_i
		data = "?last_modification_date="+t.to_s
		resp = http.get(path+data, headers)

		#puts "Number of reports found: #{reports.count}\n\n"

		results = JSON.parse(resp.body)

		printf("%-7s %-50s %-30s %-15s\n", "Scan ID", "Name", "Last Modified", "Status")
		printf("%-7s %-50s %-30s %-15s\n", "-------", "----", "-------------", "------")

		# print out all the reports
		results["scans"].each do |scan|
			printf("%-7s %-50s %-30s %-15s\n", scan["id"], scan["name"], DateTime.strptime(scan["last_modification_date"].to_s,'%s').strftime('%b %e, %Y %H:%M %Z'), scan["status"])
		end
		return results
		
	rescue StandardError => get_scanlist_error
		puts "\n\nError getting scan list: #{get_scanlist_error}\n\n"
		exit
	end
end


# This method will make the initial login request and set the token value to use for subsequent requests
def get_token(http, username, password)
	begin
		path = "/session"
		data = {'username' => username, 'password' => password}
		resp = http.post(path, data.to_json, 'Content-Type' => 'application/json')

		token = JSON.parse(resp.body)
		headers = { 
			"User-Agent" => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:25.0) Gecko/20100101 Firefox/25.0',
			"X-Cookie" => 'token=' + token["token"],
			"Accept" => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
			"Accept-Language" => 'en-us,en;q=0.5',
			"Accept-Encoding" => 'text/html;charset=UTF-8',
			"Cache-Control" => 'max-age=0',
			"Content-Type" => 'application/json'
		 }
		return headers
		
	rescue StandardError => get_token_error
		puts "\n\nError logging in/getting token: #{get_token_error}\n\n"
		exit
	end
end

### MAIN ###

options = {}
OptionParser.new do |opts|
  opts.banner = "Usage: nessus6-report-downloader.rb [options]"

  opts.on('-s', '--server SERVER', 'server ip') { |v| options[:server] = v }
  opts.on('-p', '--port PORT', 'server port')   { |v| options[:port] = v }
  opts.on('-u', '--user username', 'login username') { |v| options[:user] = v }
  opts.on('-w', '--pass password', 'login password') { |v| options[:pass] = v }
  opts.on('-t', '--type report-type', 'report type') { |v| options[:type] = v }
  opts.on('-l', '--path localpath', 'local file path for saving the reports') { |v| options[:path] = v }
  opts.on('-d', '--days DAYS', 'automatically downloads reports from the last x days, 0=today 1=yesterday and so on') { |v| options[:days] = v }

end.parse!

puts "\nNessus 6 Report Downloader 1.0"

# Collect server info
if options[:server] == nil
	print "\nEnter the Nessus Server IP: "
	nserver = gets.chomp.to_s
else
	nserver = options[:server].chomp.to_s
	puts nserver
end

if options[:port] == nil
	print "Enter the Nessus Server Port [8834]: "
	nserverport = gets.chomp.to_s
	if nserverport.eql?("")
		nserverport = "8834"
	end
else
	nserverport = options[:port].chomp.to_s
	puts nserverport
end

# https object
http = Net::HTTP.new(nserver, nserverport)	
http.use_ssl = true				
http.verify_mode = OpenSSL::SSL::VERIFY_NONE	

# Collect user/pass info
if options[:user] == nil
	print "Enter your Nessus Username: "
	username = gets.chomp.to_s
else 
	username = options[:user].chomp.to_s
	puts username
end

if options[:pass] == nil
	print "Enter your Nessus Password (will not echo): "
	password = STDIN.noecho(&:gets).chomp.to_s
else
	password = options[:pass].chomp.to_s
	puts password
end

# login and get token cookie
headers = get_token(http, username, password)
reports=""
reports_to_dl=""

# get list of reports
if options[:days] == nil
	puts "\n\nGetting report list..."
	reports = get_report_list(http, headers)
	print "Enter the report(s) your want to download (comma separate list) or 'all': "
	reports_to_dl = (gets.chomp.to_s).split(",")
else
	puts "\n\nGetting report list..."
	reports = get_report_list_lastdays(http, headers, options[:days])
	#print "Enter the report(s) your want to download (comma separate list) or 'all': "
	reports_to_dl = "all".split(",")	
end

if reports_to_dl.count == 0
	puts "\nError! You need to choose at least one report!\n\n"
	exit
end


if options[:days] == nil
	# select file types to download
	puts "\nChoose File Type(s) to Download: "
	puts "[0] Nessus (No chapter selection)"
	puts "[1] HTML"
	puts "[2] PDF"
	puts "[3] CSV (No chapter selection)"
	puts "[4] DB (No chapter selection)"
	print "Enter the file type(s) you want to download (comma separate list) or 'all': "
	filetypes_to_dl = (gets.chomp.to_s).split(",")

	if filetypes_to_dl.count == 0
		puts "\nError! You need to choose at least one file type!\n\n"
		exit
	end

	# see which file types to download
	formats = []
	cSelect = false
	dbSelect = false
	filetypes_to_dl.each do |ft|
		case ft.strip
		when "all"
		  formats.push("nessus")
		  formats.push("html")
		  formats.push("pdf")
		  formats.push("csv")
		  formats.push("db")
		  cSelect = true
		  dbSelect = true
		when "0"
		  formats.push("nessus")
		when "1"
		  formats.push("html")
	  	  cSelect = true
		when "2"
		  formats.push("pdf")
		  cSelect = true
		when "3"
		  formats.push("csv")
		when "4"
		  formats.push("db")
		  dbSelect = true
		end
	end

	# enter password used to encrypt db exports (required)
	db_export_pw = ""
	if dbSelect
		print "\nEnter a Password to encrypt the DB export (will not echo): "
		db_export_pw = STDIN.noecho(&:gets).chomp.to_s
		print "\n"
	end

	# select chapters to include, only show if html or pdf is in file type selection
	chapters = ""
	if cSelect
		puts "\nChoose Chapter(s) to Include: "
		puts "[0] Vulnerabilities By Plugin"
		puts "[1] Vulnerabilities By Host"
		puts "[2] Hosts Summary (Executive)"
		puts "[3] Suggested Remediations"
		puts "[4] Compliance Check (Executive)"
		puts "[5] Compliance Check"
		print "Enter the chapter(s) you want to include (comma separate list) or 'all': "
		chapters_to_dl = (gets.chomp.to_s).split(",")

		if chapters_to_dl.count == 0
			puts "\nError! You need to choose at least one chapter!\n\n"
			exit
		end

		# see which chapters to download
		chapters_to_dl.each do |chap|
			case chap.strip
			when "all"
			  chapters << "vuln_hosts_summary;vuln_by_plugin;vuln_by_host;remediations;compliance_exec;compliance;"
			when "0"
			  chapters << "vuln_by_plugin;"
			when "1"
			  chapters << "vuln_by_host;"
			when "2"
			  chapters << "vuln_hosts_summary;"
			when "3"
			  chapters << "remediations;"
			when "4"
			  chapters << "compliance_exec;"
			when "5"
			  chapters << "compliance;"
			end
		end
	end

	# create report folder
	print "\nPath to save reports to (without trailing slash): "
	rpath = gets.chomp.to_s
	unless File.directory?(rpath)
		FileUtils.mkdir_p(rpath)
	end

	# run report download
	if formats.count > 0
		report_download(http, headers, reports, reports_to_dl, formats, chapters, rpath, db_export_pw)
	end

	puts "\nReport Download Completed!\n\n"
else
	formats = []
	cSelect = false
	dbSelect = false
	formats.push("nessus")
	rpath = options[:path]
	report_download(http, headers, reports, reports_to_dl, formats, chapters, rpath, db_export_pw)
	puts "\nReport Download Completed!\n\n"
end
