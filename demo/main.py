from demoapp import app, db

# create the tables
with app.app_context():
    db.create_all()

def main():
    app.run(debug=True)

if __name__ == "__main__":
    main()