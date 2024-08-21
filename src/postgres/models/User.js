
import bcrypt from 'bcrypt';
import { dbconfig } from "../dbconfig.js";

class User {

 
  async add_user(data) {
    const { login, email, password } = data;
    
   
    const salt = await bcrypt.genSalt();
    const hash = await bcrypt.hash(password, salt);
    
  
    const user = await dbconfig.query(
      "INSERT INTO users(login, email, password) VALUES($1, $2, $3) RETURNING *",
      [login, email, hash]
    );
    
    return user.rows[0];
  }


  async findUserByLogin(login) {
    const user = await dbconfig.query("SELECT * FROM users WHERE login = $1", [login]);
    return user.rows[0]; 
  }

  
  async authenticate_user(login, password) {
    const user = await this.findUserByLogin(login);
    if (user && await bcrypt.compare(password, user.password)) {
      return user;
    }
    throw new Error('Invalid credentials');  
  }

  
  async get_all_users() {
    const users = await dbconfig.query("SELECT * FROM users");
    return users.rows;  
  }
}

export default new User();
