from flask import Flask
from flask_pymongo import PyMongo
from pymisp import PyMISP
from .config import Config

mongo = PyMongo()

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    mongo.init_app(app)

    with app.app_context():
        app.misp = PyMISP(
            app.config['MISP_URL'],
            app.config['MISP_KEY'],
            app.config['MISP_VERIFYCERT']
        )

    # ✅ Ensure Blueprint is imported **after** app initialization
    from .views import main
    app.register_blueprint(main)  # ✅ Register Blueprint only once

    return app
