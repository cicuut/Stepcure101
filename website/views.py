from flask import  Blueprint, render_template, request, jsonify, send_file
import plotly
from pymongo import MongoClient
from .models import Risk, Asset, AssessmentProgress
from .misp_utils import fetch_recent_threats, calculate_risk
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import plotly.graph_objs as go
import json
import numpy as np
import pdfkit
import os
from bson.objectid import ObjectId
from bson import ObjectId
from io import BytesIO
from bson.json_util import dumps
from flask_pymongo import PyMongo


# ✅ Define Blueprint at the top (not repeated)
main = Blueprint('main', __name__)

@main.route('/')
def index():
    risks = Risk.get_all()
    # Ensure that each risk includes the 'impact' field and data is correctly passed to the template
    print("Risks fetched from MongoDB:", risks)
    return render_template('index.html', risks=risks)


@main.route('/create_assessment', methods=['POST'])
def create_assessment():
    """Create a new assessment and return its ID."""
    new_assessment = AssessmentProgress.create()
    return jsonify({"message": "New assessment created", "assessment_id": str(new_assessment.inserted_id)})

@main.route('/graphic_risks')
def graphic_risks():
    # Fetch all risks
    risks = Risk.get_all()

    if not risks:
        return jsonify({'data': [], 'layout': {}})  # Return empty data if no risks

    # Define a dictionary to hold the counts of each risk level per year
    risk_levels = ['Low', 'Moderate', 'High', 'Critical']
    risk_data = {level: {} for level in risk_levels}

    # Process each risk to group by year and risk level
    for risk in risks:
        try:
            # Extract year from 'date_assignment', make sure it is a datetime object
            year = str(risk['date_assignment'][:4])  # Assuming 'date_assignment' is in 'YYYY-MM-DD' format
            risk_level = risk['risk_level']
            
            if risk_level in risk_data:
                if year not in risk_data[risk_level]:
                    risk_data[risk_level][year] = 0
                risk_data[risk_level][year] += 1
        except Exception as e:
            print(f"Error processing risk: {e}")

    # Get all unique years sorted
    years = sorted(set(year for level in risk_data.values() for year in level.keys()))

    # Collect risk counts by year for each risk level
    low_risk_counts = [risk_data['Low'].get(year, 0) for year in years]
    moderate_risk_counts = [risk_data['Moderate'].get(year, 0) for year in years]
    high_risk_counts = [risk_data['High'].get(year, 0) for year in years]
    critical_risk_counts = [risk_data['Critical'].get(year, 0) for year in years]

    # Create Plotly chart
    fig = go.Figure()

    fig.add_trace(go.Bar(
        x=years,
        y=low_risk_counts,
        name='Low',
        marker_color='green'
    ))

    fig.add_trace(go.Bar(
        x=years,
        y=moderate_risk_counts,
        name='Moderate',
        marker_color='yellow'
    ))

    fig.add_trace(go.Bar(
        x=years,
        y=high_risk_counts,
        name='High',
        marker_color='red'
    ))

    fig.add_trace(go.Bar(
        x=years,
        y=critical_risk_counts,
        name='Critical',
        marker_color='darkred'
    ))

    fig.update_layout(
        barmode='stack',
        title='Risk Level Distribution by Year',
        xaxis_title='Year',
        yaxis_title='Risk Count',
        xaxis=dict(tickmode='array', tickvals=years),
        yaxis=dict(title='Number of Risks'),
        legend_title='Risk Level'
    )

    # Return chart as JSON data
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

@main.route('/submit_step', methods=['POST'])
def submit_step():
    """Update step status for a given assessment."""
    data = request.json
    assessment_id = data.get("assessment_id")
    step = str(data.get("step"))
    status = data.get("status", "complete")  # Default to "complete"

    if not assessment_id:
        return jsonify({"error": "Missing assessment_id"}), 400  # Return error with status 400

    # Find the assessment and update the step status
    assessment = AssessmentProgress.get_by_id(assessment_id)
    if assessment:
        steps = assessment.get("steps", {})
        steps[str(step)] = status  # Update the specific step's status
        
        # Update the assessment in the database
        result = AssessmentProgress.update(assessment_id, {"steps": steps})
        if result:
            return jsonify({"message": f"Step {step} updated to {status} for assessment {assessment_id}."}), 200  # Success
        else:
            return jsonify({"error": "Failed to update assessment progress."}), 500  # Error with status 500
    else:
        return jsonify({"error": "Assessment not found."}), 404  # Error if assessment not found


@main.route('/add_risk', methods=['POST'])
def add_risk():
    data = request.json
    print("Received data:", data)  # Debugging: cek data yang diterima

    # Pastikan impact diubah menjadi integer jika belum
    impact = int(data.get('impact', 0))  # Default ke 0 jika tidak ada

    # Tentukan threat_scenario yang lebih deskriptif
    threat_scenario = data.get('threat_scenario', f"Potential exploitation by {data.get('threat_actor', 'Unknown Actor')}")

    risk_data = {
        'asset': data.get('asset'),
        'date_assignment': data.get('date_assignment'),
        'critical_asset': data.get('critical_asset'),
        'importance': data.get('importance'),
        'asset_location': data.get('asset_location'),
        'asset_value': data.get('asset_value'),
        'threat_actor': data.get('threat_actor'),
        'threat_intent': data.get('threat_intent'),
        'external_threat': data.get('external_threat'),
        'risk_impact_area': data.get('risk_impact_area'),
        'impact_description': data.get('impact_description'),
        'security_controls': data.get('security_controls'),
        'control_effectiveness': data.get('control_effectiveness'),
        'control_gaps': data.get('control_gaps'),
        'impact': impact,
        'likelihood': data.get('likelihood'),
        'risk_description': data.get('risk_description'),
        'business_impact': data.get('business_impact'),
        'financial_impact': data.get('financial_impact'),
        'risk_priority': data.get('risk_priority'),
        'risk_mitigation': data.get('risk_mitigation'),
        'mitigation_strategy': data.get('mitigation_strategy'),
        'resource_needs': data.get('resource_needs'),
        'risk_level': data.get('risk_level'),
        'threat_scenario': threat_scenario  # Pastikan threat_scenario dimasukkan dengan baik
    }

    print("Storing risk data:", risk_data)  # Debugging: cek data yang akan disimpan
    risk_id = Risk.create(risk_data)

    return jsonify({"message": "Risk added successfully", "id": str(risk_id)})  # Kirim ID risk yang baru



@main.route('/fetch_risks', methods=['GET'])
def fetch_risks():
    risks = Risk.get_all()
    # Log risks to verify the impact field is being retrieved properly
    print("Fetched risks:", risks)
    return dumps(risks)


@main.route('/add_asset', methods=['POST'])
def add_asset():
    data = request.json
    asset_id = Asset.create(data)
    return jsonify({"message": "Asset added successfully", "id": str(asset_id.inserted_id)})

@main.route('/fetch_assets')
def fetch_assets():
    assets = Asset.get_all()
    return dumps(assets)

@main.route('/recent_threats')
def recent_threats():
    threats = fetch_recent_threats(limit=10)
    
    for threat in threats:
        threat['threat_actor'] = next((attr['value'] for attr in threat['attributes'] if attr['type'] == 'threat-actor'), "Unknown")
        threat['threat_scenario'] = f"Exploited {threat['info']}"
        threat['risk_impact_area'] = next((tag for tag in threat['tags'] if tag.startswith('impact:')), "Unknown")
        threat['likelihood'] = "Moderate" if threat["threat_level"] == 2 else "High"
        threat['risk_level'] = calculate_risk(3 if threat["threat_level"] >= 3 else threat["threat_level"], 2 if threat['likelihood'] == "Moderate" else 3)
    
    return render_template('recent_threats.html', threats=threats)

@main.route('/assess_risk', methods=['POST'])
def assess_risk():
    data = request.json
    impact = int(data['impact'])
    likelihood = int(data['likelihood'])

    risk_level = calculate_risk(impact, likelihood)

    risk_data = {
        'asset': data['asset'],
        'threat_actor': data['threat_actor'],
        'threat_scenario': data['threat_scenario'],
        'risk_impact_area': data['risk_impact_area'],
        'impact': impact,
        'likelihood': likelihood,
        'risk_level': risk_level
    }

    Risk.create(risk_data)

    return jsonify({'risk_level': risk_level})

@main.route('/visualize_risks')
def visualize_risks():
    risks = Risk.get_all()
    
    if not risks:
        return jsonify({'data': [], 'layout': {}})

    risk_levels = {'Low': 1, 'Moderate': 2, 'High': 3, 'Critical': 4}
    risk_data = {}

    for risk in risks:
        year = risk['assessment_date'].year
        if year not in risk_data:
            risk_data[year] = []
        risk_data[year].append(risk_levels[risk['risk_level']])

    years = sorted(risk_data.keys())
    avg_risk_levels = [np.mean(risk_data[year]) for year in years]

    fig = go.Figure(data=go.Bar(
        x=years,
        y=avg_risk_levels,
        marker_color=['green' if level < 2 else 'yellow' if level < 3 else 'red' for level in avg_risk_levels]
    ))
    
    fig.update_layout(
        title='Average Risk Level by Year',
        xaxis_title='Year',
        yaxis_title='Average Risk Level',
        yaxis=dict(tickmode='array', tickvals=[1, 2, 3, 4], ticktext=['Low', 'Moderate', 'High', 'Critical'])
    )
    
    return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

@main.route('/get_risk/<id>', methods=['GET'])
def get_risk(id):
    try:
        risk = Risk.get_risk_by_id(id)
        if risk:
            return jsonify(risk)
        return jsonify({"error": "Risk not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ API untuk mendapatkan semua data step 1-8
@main.route('/get_assessment/<id>', methods=['GET'])
def get_assessment(id):
    assessment = AssessmentProgress.get_by_id(id)
    if assessment:
        return jsonify(assessment)
    return jsonify({"error": "Assessment not found"}), 404

# ✅ API untuk update semua data step 1-8
@main.route('/update_assessment', methods=['POST'])
def update_assessment():
    data = request.json
    assessment_id = data.get("assessment_id")
    updated_data = data.get("updated_data")

    if not assessment_id or not updated_data:
        return jsonify({"error": "Missing data"}), 400

    result = AssessmentProgress.update(assessment_id, updated_data)
    if result.modified_count > 0:
        return jsonify({"message": "Assessment updated successfully"})
    return jsonify({"error": "Update failed"}), 500

# ✅ API untuk delete semua data step 1-8
@main.route('/delete_assessment/<id>', methods=['DELETE'])
def delete_assessment(id):
    result = AssessmentProgress.delete(id)
    if result.deleted_count > 0:
        return jsonify({"message": "Assessment deleted successfully"})
    return jsonify({"error": "Failed to delete assessment"}), 500

# ✅ API untuk download PDF berisi semua data step 1-8
@main.route('/download_pdf/<id>', methods=['GET'])
def download_pdf(id):
    try:
        risk = Risk.get_risk_by_id(id)

        if not risk:
            return jsonify({"error": "Risk not found"}), 404

        # Create PDF from risk data
        pdf_buffer = BytesIO()
        p = canvas.Canvas(pdf_buffer, pagesize=letter)
        width, height = letter

        p.setFont("Helvetica-Bold", 16)
        p.drawString(200, height - 50, "Risk Assessment Report")

        p.setFont("Helvetica", 12)
        y_position = height - 100

        # Define questions and data points for each step
        questions_and_answers = [
            ("Step 1: Asset Identification", [
                ("Information Asset", risk.get('asset', 'N/A')),
                ("Critical Asset", risk.get('critical_asset', 'N/A')),
                ("Importance of Asset", risk.get('importance', 'N/A')),
                ("Asset Location", risk.get('asset_location', 'N/A')),
                ("Asset Value", risk.get('asset_value', 'N/A')),
            ]),
            ("Step 2: Environmental Threats", [
                ("Threat Actor", risk.get('threat_actor', 'N/A')),
                ("Threat Intent", risk.get('threat_intent', 'N/A')),
                ("External Threat Factors", risk.get('external_threat', 'N/A')),
            ]),
            ("Step 3: Impact Area", [
                ("Risk Impact Area", risk.get('risk_impact_area', 'N/A')),
                ("Impact Description", risk.get('impact_description', 'N/A')),
            ]),
            ("Step 4: Existing Controls", [
                ("Security Controls", risk.get('security_controls', 'N/A')),
                ("Control Effectiveness", risk.get('control_effectiveness', 'N/A')),
                ("Control Gaps", risk.get('control_gaps', 'N/A')),
            ]),
            ("Step 5: Risk Evaluation", [
                ("Impact", risk.get('impact', 'N/A')),
                ("Likelihood", risk.get('likelihood', 'N/A')),
                ("Risk Description", risk.get('risk_description', 'N/A')),
            ]),
            ("Step 6: Impact to Business", [
                ("Business Impact", risk.get('business_impact', 'N/A')),
                ("Financial Impact", risk.get('financial_impact', 'N/A')),
            ]),
            ("Step 7: Risk Prioritization", [
                ("Risk Priority", risk.get('risk_priority', 'N/A')),
                ("Risk Mitigation", risk.get('risk_mitigation', 'N/A')),
            ]),
            ("Step 8: Mitigation Strategy", [
                ("Mitigation Strategy", risk.get('mitigation_strategy', 'N/A')),
                ("Resource Needs", risk.get('resource_needs', 'N/A')),
            ]),
            ("Risk Level", [
                  ("Risk Level", risk.get('risk_level', 'N/A')),
            ]),
        ]

        # Loop through each step, add question and answer to PDF
        for step_title, questions in questions_and_answers:
            if y_position < 100:  # Check if we need to start a new page
                p.showPage()
                p.setFont("Helvetica-Bold", 16)
                p.drawString(200, height - 50, "Risk Assessment Report")
                y_position = height - 100

            p.setFont("Helvetica-Bold", 14)
            p.drawString(50, y_position, step_title)
            y_position -= 20

            for question, answer in questions:
                p.setFont("Helvetica-Bold", 12)
                p.drawString(50, y_position, f"{question}:")
                p.setFont("Helvetica", 12)
                p.drawString(200, y_position, str(answer))
                y_position -= 30  # Move to next line

            y_position -= 10  # Add space between steps

        p.showPage()
        p.save()

        pdf_buffer.seek(0)

        return send_file(pdf_buffer, as_attachment=True, download_name=f"Risk_Report_{id}.pdf", mimetype="application/pdf")

    except Exception as e:
        return jsonify({"error": f"Failed to generate PDF: {str(e)}"}), 500
