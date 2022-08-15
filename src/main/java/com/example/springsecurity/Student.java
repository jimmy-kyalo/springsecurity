package com.example.springsecurity;

public class Student {
    private final Integer studentId;
    private final String studentName;

    public Student(Integer studentId, String studentName) {
        this.studentId = studentId;
        this.studentName = studentName;
    }

    public Integer getStudentId() {
        return this.studentId;
    }

    public String getStudentName() {
        return this.studentName;
    }

    @Override
    public String toString() {
        return "{" +
                " studentId='" + getStudentId() + "'" +
                ", studentName='" + getStudentName() + "'" +
                "}";
    }

}
