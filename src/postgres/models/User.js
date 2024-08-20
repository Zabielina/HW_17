import { dbconfig } from "../dbconfig.js";
import bcrypt from "bcrypt"
class User {
  async add_user(data) {
    const { login, email, password } = data;
    const salt = await bcrypt.genSalt()
    const hash = await bcrypt.hash(data.password, salt)
    const user = await dbconfig.query(
      "INSERT INTO users(login, email, password) VALUES($1,$2,$3) RETURNING *",
      [data.login, data.email, hash]
    );
    return user.rows[0].id;


  }

  async delete_users(id) {

    const user = await dbconfig.query(
      "DELETE  FROM users WHERE id = $1",
      [id]

    );
    return user.rowCount;
  }


  async get_all_users() {

    const user = await dbconfig.query(
      "SELECT * FROM users"

    );
    return user.rows;
  }
}

export default new User();
