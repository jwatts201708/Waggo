import Person from "../models/Person.js";

export const getPeople = async (req, res) => {
  try {
    const people = await Person.find();
    res.json(people);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
};

export const createPerson = async (req, res) => {
  try {
    const person = new Person(req.body);
    await person.save();
    res.json(person);
  } catch (err) {
    res.status(500).json({ error: "Server error" });
  }
};

