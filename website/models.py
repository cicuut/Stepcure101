from bson import ObjectId
from . import mongo

class Risk:
    @staticmethod
    def create(data):
        if 'date_assignment' not in data or not data['date_assignment']:
            from datetime import datetime
            data['date_assignment'] = datetime.now().strftime("%Y-%m-%d")  
        inserted_risk = mongo.db.risks.insert_one(data)
        return inserted_risk.inserted_id  # ✅ Kembalikan ID risk yang baru dibuat


    @staticmethod
    def get_all():
        return list(mongo.db.risks.find())

    @staticmethod
    def get_risk_by_id(risk_id):
        """Mengambil satu risk berdasarkan ObjectId"""
        return mongo.db.risks.find_one({"_id": ObjectId(risk_id)})
class Asset:
    @staticmethod
    def create(data):
        return mongo.db.assets.insert_one(data)

    @staticmethod
    def get_all():
        return list(mongo.db.assets.find())


class AssessmentProgress:
    @staticmethod
    def create():
        """Create a new assessment with all steps marked as incomplete."""
        data = {
            "steps": {str(i): "incomplete" for i in range(1, 9)}
        }
        return mongo.db.assessment_progress.insert_one(data)

    @staticmethod
    def get_all():
        return list(mongo.db.assessment_progress.find())

    @staticmethod
    def get_by_id(assessment_id):
        return mongo.db.assessment_progress.find_one({"_id": ObjectId(assessment_id)})

    @staticmethod
    def update(assessment_id, data):
        return mongo.db.assessment_progress.update_one(
            {"_id": ObjectId(assessment_id)},
            {"$set": data}
        )

    @staticmethod
    def submit_step(assessment_id, step_number, status="complete"):
        """Mark a step as complete or incomplete in the database."""
        assessment = mongo.db.assessment_progress.find_one({"_id": ObjectId(assessment_id)})
        if not assessment:
            return None
        
        steps = assessment.get("steps", {str(i): "incomplete" for i in range(1, 9)})  # Default to incomplete
        steps[str(step_number)] = status  # Set the step's status

        return mongo.db.assessment_progress.update_one(
            {"_id": ObjectId(assessment_id)},
            {"$set": {"steps": steps}}
        )

