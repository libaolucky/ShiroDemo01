package com.xiexin.bean;

import java.io.Serializable;

/**
 * quan_xian
 * @author 
 */
public class QuanXian implements Serializable {
    private Integer quanXianId;

    /**
     * 菜单权限编码
     */
    private String quanXianCode;

    /**
     * 菜单权限名称
     */
    private String quanXianName;

    /**
     * 授权(如：sys:user:add)
     */
    private String quanXianPerms;

    private String quanXianUrl;

    private String quanXianMethod;

    private Integer quanXianPid;

    private Integer quanXianOrder;

    private Integer quanXianType;

    private Integer quanXianStatus;

    private static final long serialVersionUID = 1L;

    public Integer getQuanXianId() {
        return quanXianId;
    }

    public void setQuanXianId(Integer quanXianId) {
        this.quanXianId = quanXianId;
    }

    public String getQuanXianCode() {
        return quanXianCode;
    }

    public void setQuanXianCode(String quanXianCode) {
        this.quanXianCode = quanXianCode;
    }

    public String getQuanXianName() {
        return quanXianName;
    }

    public void setQuanXianName(String quanXianName) {
        this.quanXianName = quanXianName;
    }

    public String getQuanXianPerms() {
        return quanXianPerms;
    }

    public void setQuanXianPerms(String quanXianPerms) {
        this.quanXianPerms = quanXianPerms;
    }

    public String getQuanXianUrl() {
        return quanXianUrl;
    }

    public void setQuanXianUrl(String quanXianUrl) {
        this.quanXianUrl = quanXianUrl;
    }

    public String getQuanXianMethod() {
        return quanXianMethod;
    }

    public void setQuanXianMethod(String quanXianMethod) {
        this.quanXianMethod = quanXianMethod;
    }

    public Integer getQuanXianPid() {
        return quanXianPid;
    }

    public void setQuanXianPid(Integer quanXianPid) {
        this.quanXianPid = quanXianPid;
    }

    public Integer getQuanXianOrder() {
        return quanXianOrder;
    }

    public void setQuanXianOrder(Integer quanXianOrder) {
        this.quanXianOrder = quanXianOrder;
    }

    public Integer getQuanXianType() {
        return quanXianType;
    }

    public void setQuanXianType(Integer quanXianType) {
        this.quanXianType = quanXianType;
    }

    public Integer getQuanXianStatus() {
        return quanXianStatus;
    }

    public void setQuanXianStatus(Integer quanXianStatus) {
        this.quanXianStatus = quanXianStatus;
    }

    @Override
    public boolean equals(Object that) {
        if (this == that) {
            return true;
        }
        if (that == null) {
            return false;
        }
        if (getClass() != that.getClass()) {
            return false;
        }
        QuanXian other = (QuanXian) that;
        return (this.getQuanXianId() == null ? other.getQuanXianId() == null : this.getQuanXianId().equals(other.getQuanXianId()))
            && (this.getQuanXianCode() == null ? other.getQuanXianCode() == null : this.getQuanXianCode().equals(other.getQuanXianCode()))
            && (this.getQuanXianName() == null ? other.getQuanXianName() == null : this.getQuanXianName().equals(other.getQuanXianName()))
            && (this.getQuanXianPerms() == null ? other.getQuanXianPerms() == null : this.getQuanXianPerms().equals(other.getQuanXianPerms()))
            && (this.getQuanXianUrl() == null ? other.getQuanXianUrl() == null : this.getQuanXianUrl().equals(other.getQuanXianUrl()))
            && (this.getQuanXianMethod() == null ? other.getQuanXianMethod() == null : this.getQuanXianMethod().equals(other.getQuanXianMethod()))
            && (this.getQuanXianPid() == null ? other.getQuanXianPid() == null : this.getQuanXianPid().equals(other.getQuanXianPid()))
            && (this.getQuanXianOrder() == null ? other.getQuanXianOrder() == null : this.getQuanXianOrder().equals(other.getQuanXianOrder()))
            && (this.getQuanXianType() == null ? other.getQuanXianType() == null : this.getQuanXianType().equals(other.getQuanXianType()))
            && (this.getQuanXianStatus() == null ? other.getQuanXianStatus() == null : this.getQuanXianStatus().equals(other.getQuanXianStatus()));
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((getQuanXianId() == null) ? 0 : getQuanXianId().hashCode());
        result = prime * result + ((getQuanXianCode() == null) ? 0 : getQuanXianCode().hashCode());
        result = prime * result + ((getQuanXianName() == null) ? 0 : getQuanXianName().hashCode());
        result = prime * result + ((getQuanXianPerms() == null) ? 0 : getQuanXianPerms().hashCode());
        result = prime * result + ((getQuanXianUrl() == null) ? 0 : getQuanXianUrl().hashCode());
        result = prime * result + ((getQuanXianMethod() == null) ? 0 : getQuanXianMethod().hashCode());
        result = prime * result + ((getQuanXianPid() == null) ? 0 : getQuanXianPid().hashCode());
        result = prime * result + ((getQuanXianOrder() == null) ? 0 : getQuanXianOrder().hashCode());
        result = prime * result + ((getQuanXianType() == null) ? 0 : getQuanXianType().hashCode());
        result = prime * result + ((getQuanXianStatus() == null) ? 0 : getQuanXianStatus().hashCode());
        return result;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append(" [");
        sb.append("Hash = ").append(hashCode());
        sb.append(", quanXianId=").append(quanXianId);
        sb.append(", quanXianCode=").append(quanXianCode);
        sb.append(", quanXianName=").append(quanXianName);
        sb.append(", quanXianPerms=").append(quanXianPerms);
        sb.append(", quanXianUrl=").append(quanXianUrl);
        sb.append(", quanXianMethod=").append(quanXianMethod);
        sb.append(", quanXianPid=").append(quanXianPid);
        sb.append(", quanXianOrder=").append(quanXianOrder);
        sb.append(", quanXianType=").append(quanXianType);
        sb.append(", quanXianStatus=").append(quanXianStatus);
        sb.append(", serialVersionUID=").append(serialVersionUID);
        sb.append("]");
        return sb.toString();
    }
}