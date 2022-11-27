from flask import Flask, jsonify, request, render_template, send_file, flash, redirect
import logging
from datetime import datetime
import os
import configparser
from traffic_analysis import TrafficAnalyzer
from werkzeug.utils import secure_filename

#### Global Variables ####
# Check config parser
UPLOAD_FOLDER = 'uploads/'
ALLOWED_EXTENSIONS = {'json'}
traffic = TrafficAnalyzer('configs/traffic_config.ini')

## FLASK ##
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
##Webpages
@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/filelist')
def dir_listing():
    files = os.listdir('./outputs')
    return render_template('list.html', files=files)

@app.route('/check_stats')
def display_stats():
    stats = traffic.stats.eval_to_json()
    return render_template('stats.html', stats=stats)

@app.route('/load_stats_button', methods = ['POST', 'GET'])
def load_stats_button():
    return render_template('upload.html')

@app.route('/save_stats_button', methods = ['POST', 'GET'])
def save_stats_button():
    res = save_stats()
    logger.info(res.json)
    if res.json['success'] == True:
        flash('Save Sucessful')
    else:
        flash('There was an error')
    return redirect('http://localhost:5002/index', code=302)

@app.route('/reset_stats_button', methods = ['POST', 'GET'])
def reset():
    if traffic.stats.reset_stats():
        flash('Reset Sucessful')
    else:
        flash('There was an error')
    return redirect('http://localhost:5002/index', code=302)

@app.route('/upload', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect('/index', code=302)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No file selected')
            return redirect('/index', code=302)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            if traffic.stats.load_stats(os.path.join(app.config['UPLOAD_FOLDER'], filename)) == True:
                flash('Load Sucessful')
            else:
                flash('There was an error loading the file')
                return redirect('/index', code=302)
        else: 
            flash('Invalid file path, must be csv')
            return redirect('/index', code=302)
    
    return redirect('/index', code=302)

@app.route('/download', methods=['GET'])
def download():
    file = request.args.get('file')
    if file is not None:
        path = "./outputs/%s" % file
        if os.path.isfile(path):
            return send_file(path, as_attachment=True)
    
    files = os.listdir('./outputs')
    return render_template('list.html', files=files)

##REST Endpoints
@app.route('/toggle_retroactive', methods= ['GET'])
def toggle_retroactive():
    traffic.config.retroactive_list = not traffic.config.retroactive_list
    return jsonify({
            "code": 200, 
            "current_retroactive_value":  traffic.config.retroactive_list}) 

@app.route('/save_stats', methods = ['GET'])
def save_stats():
    filename = './outputs/' + 'packet_logs_' + str(datetime.now().strftime("%Y_%m_%d-%I:%M:%S_%p")) + '.json'
    res = traffic.stats.save_stats(filename)
    if res == True:
        return jsonify({"code": "200", "success": True, "filename": filename})
    else:
        return jsonify({"code": "500", "success": False, "filename": None})

@app.route('/stats_time', methods= ['GET'])
def get_stats_time():
    return traffic.stats.time_to_json()

@app.route('/stats_eval', methods= ['GET'])
def get_stats():
    return traffic.stats.eval_to_json()

@app.route('/stats_domain', methods = ['GET'])
def get_stats_domain():
    return traffic.stats.domains_to_json()

@app.route('/all_stats', methods = ['GET'])
def get_all_stats():
    return traffic.stats.get_all_stats()

@app.route('/analyze_http', methods=['POST'])
def parse_http():
    packet = request.json
    if debug_level == True:
        logger.info('Received HTTP Request')
        logger.info(packet)
    if verify_packet_format_http(packet) == True:
        result = traffic.analyze_http(packet)
        return gen_response(result['value'], result['domain'], result['source'])
    else:
        return jsonify({
            "code": 400, 
            "message": "Bad format for http request (check Documentation)"})
    

@app.route('/analyze_dns', methods= ['POST'])
def parse_packet():
    packet = request.json
    if debug_level == True:
        logger.info('Receive DNS Request')
        logger.info(packet)
    if verify_packet_format_dns(packet) == True:
        result = traffic.analyze_dns(packet)
        return gen_response(result['value'], result['domain'], result['source'])
    else:
        return jsonify({
            "code": 400, 
            "message": "Bad format for http request (check Documentation)"}) 

@app.route('/list_files', methods=['GET'])
def get_file_list():
    files = os.listdir('./outputs')
    return jsonify({
        "code": 200,
        "files_available" : files
    })

#Helper Functions
def gen_response(val, domain, source):
    """Converts the response from the analyzer into json format

    Args:
        val (string): valuation of the analysis
        domain (string): flagged domain
        source (string): source domain

    Returns:
        dict: jsonified version on input
    """

    return jsonify({
        "code": 200,
        "prediction": str(val),
        "domain": str(domain),
        "source": str(source)
        }
    )

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def verify_packet_format_http(packet):
    try:
        assert(type(packet['source']) == int)
        assert(type(packet['destination']) == int)
        assert(type(packet['timestamp']) == int)
        assert(type(packet['domain']) == str)
        if debug_level == True:
            logger.info('Parsed HTTP request sucessfully')
        return True
    except:
        if debug_level == True:
            logger.info('Failed to parse HTTP request')
        return False

def verify_packet_format_dns(packet):
    try:
        assert(type(packet['source']) == int)
        assert(type(packet['destination']) == int)
        assert(type(packet['length']) == int)
        assert(type(packet['nr_of_requests']) == int)
        assert(type(packet['question_type']) == int)
        assert(type(packet['queries_null']) == int)
        assert(type(packet['timestamp']) == int)
        assert(type(packet['domain']) == str)
        if debug_level == True:
            logger.info('Parsed DNS request sucessfully')
        return True
    except Exception as e:
        if debug_level == True:
            logger.info('Failed to parse DNS request')
        return False

#Other
def parse_config(path):
    global secret_key, debug_level
    config = configparser.ConfigParser()
    config.read(path)
    #Main 
    secret_key = config['GENERAL']['SecretKey']
    debug_level = True if config['GENERAL']['Debug'] == 'True' else False


if __name__ == '__main__':

    logging.basicConfig(filename="logs/log_file.log")

    logger = logging.getLogger('logger')
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s:  %(message)s')

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)
    logger.info("\n---------------------\n\n")

    ### Program Start
    parse_config('configs/general_config.ini')
    

    app.secret_key = secret_key
    app.run(debug=True, host='0.0.0.0', port = '5002')

