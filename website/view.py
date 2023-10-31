from flask import Blueprint,render_template,request,flash,jsonify
from flask_login import login_required,current_user
from .models import note
from . import db
import json
views=Blueprint('views',__name__)

@views.route('/',methods=['GET','POST'])
@login_required
def home():
    if request.method=='POST':
        Note=request.form.get('note')
        if len(Note)<1:
              flash('note is too short',category='error')
        else:
             new_note=note(data=Note,user_id=current_user.id)
             db.session.add(new_note)
             db.session.commit()
             flash('note added',category='success')

    return render_template("home.html",user=current_user)

     
@views.route('/deletenote', methods=['POST'])
def delete_note():  
    Note = json.loads(request.data) 
    noteId = Note['noteId']
    Note = note.query.get(noteId)
    if Note:
        if Note.user_id == current_user.id:
            db.session.delete(Note)
            db.session.commit()

    return jsonify({})



