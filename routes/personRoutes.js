import express from "express";
import { getPeople, createPerson } from "../controllers/personController.js";

const router = express.Router();

router.get("/", getPeople);
router.post("/", createPerson);

export default router;

