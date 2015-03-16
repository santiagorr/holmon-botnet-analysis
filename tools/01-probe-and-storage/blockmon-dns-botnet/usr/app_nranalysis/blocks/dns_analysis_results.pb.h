// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: dns_analysis_results.proto

#ifndef PROTOBUF_dns_5fanalysis_5fresults_2eproto__INCLUDED
#define PROTOBUF_dns_5fanalysis_5fresults_2eproto__INCLUDED

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 2004000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 2004001 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/generated_message_reflection.h>
// @@protoc_insertion_point(includes)

// Internal implementation detail -- do not call these.
void  protobuf_AddDesc_dns_5fanalysis_5fresults_2eproto();
void protobuf_AssignDesc_dns_5fanalysis_5fresults_2eproto();
void protobuf_ShutdownFile_dns_5fanalysis_5fresults_2eproto();

class dns_analysis_results;
class dns_analysis_results_DataMessage;
class dns_analysis_results_ControlMessage;

// ===================================================================

class dns_analysis_results_DataMessage : public ::google::protobuf::Message {
 public:
  dns_analysis_results_DataMessage();
  virtual ~dns_analysis_results_DataMessage();
  
  dns_analysis_results_DataMessage(const dns_analysis_results_DataMessage& from);
  
  inline dns_analysis_results_DataMessage& operator=(const dns_analysis_results_DataMessage& from) {
    CopyFrom(from);
    return *this;
  }
  
  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }
  
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }
  
  static const ::google::protobuf::Descriptor* descriptor();
  static const dns_analysis_results_DataMessage& default_instance();
  
  void Swap(dns_analysis_results_DataMessage* other);
  
  // implements Message ----------------------------------------------
  
  dns_analysis_results_DataMessage* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const dns_analysis_results_DataMessage& from);
  void MergeFrom(const dns_analysis_results_DataMessage& from);
  void Clear();
  bool IsInitialized() const;
  
  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:
  
  ::google::protobuf::Metadata GetMetadata() const;
  
  // nested types ----------------------------------------------------
  
  // accessors -------------------------------------------------------
  
  // required string dname = 1;
  inline bool has_dname() const;
  inline void clear_dname();
  static const int kDnameFieldNumber = 1;
  inline const ::std::string& dname() const;
  inline void set_dname(const ::std::string& value);
  inline void set_dname(const char* value);
  inline void set_dname(const char* value, size_t size);
  inline ::std::string* mutable_dname();
  inline ::std::string* release_dname();
  
  // required uint32 timestamp = 2;
  inline bool has_timestamp() const;
  inline void clear_timestamp();
  static const int kTimestampFieldNumber = 2;
  inline ::google::protobuf::uint32 timestamp() const;
  inline void set_timestamp(::google::protobuf::uint32 value);
  
  // required bool whitelisted = 3;
  inline bool has_whitelisted() const;
  inline void clear_whitelisted();
  static const int kWhitelistedFieldNumber = 3;
  inline bool whitelisted() const;
  inline void set_whitelisted(bool value);
  
  // required float score = 4;
  inline bool has_score() const;
  inline void clear_score();
  static const int kScoreFieldNumber = 4;
  inline float score() const;
  inline void set_score(float value);
  
  // @@protoc_insertion_point(class_scope:dns_analysis_results.DataMessage)
 private:
  inline void set_has_dname();
  inline void clear_has_dname();
  inline void set_has_timestamp();
  inline void clear_has_timestamp();
  inline void set_has_whitelisted();
  inline void clear_has_whitelisted();
  inline void set_has_score();
  inline void clear_has_score();
  
  ::google::protobuf::UnknownFieldSet _unknown_fields_;
  
  ::std::string* dname_;
  ::google::protobuf::uint32 timestamp_;
  bool whitelisted_;
  float score_;
  
  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(4 + 31) / 32];
  
  friend void  protobuf_AddDesc_dns_5fanalysis_5fresults_2eproto();
  friend void protobuf_AssignDesc_dns_5fanalysis_5fresults_2eproto();
  friend void protobuf_ShutdownFile_dns_5fanalysis_5fresults_2eproto();
  
  void InitAsDefaultInstance();
  static dns_analysis_results_DataMessage* default_instance_;
};
// -------------------------------------------------------------------

class dns_analysis_results_ControlMessage : public ::google::protobuf::Message {
 public:
  dns_analysis_results_ControlMessage();
  virtual ~dns_analysis_results_ControlMessage();
  
  dns_analysis_results_ControlMessage(const dns_analysis_results_ControlMessage& from);
  
  inline dns_analysis_results_ControlMessage& operator=(const dns_analysis_results_ControlMessage& from) {
    CopyFrom(from);
    return *this;
  }
  
  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }
  
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }
  
  static const ::google::protobuf::Descriptor* descriptor();
  static const dns_analysis_results_ControlMessage& default_instance();
  
  void Swap(dns_analysis_results_ControlMessage* other);
  
  // implements Message ----------------------------------------------
  
  dns_analysis_results_ControlMessage* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const dns_analysis_results_ControlMessage& from);
  void MergeFrom(const dns_analysis_results_ControlMessage& from);
  void Clear();
  bool IsInitialized() const;
  
  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:
  
  ::google::protobuf::Metadata GetMetadata() const;
  
  // nested types ----------------------------------------------------
  
  // accessors -------------------------------------------------------
  
  // required uint32 timestamp = 1;
  inline bool has_timestamp() const;
  inline void clear_timestamp();
  static const int kTimestampFieldNumber = 1;
  inline ::google::protobuf::uint32 timestamp() const;
  inline void set_timestamp(::google::protobuf::uint32 value);
  
  // required bool start = 2;
  inline bool has_start() const;
  inline void clear_start();
  static const int kStartFieldNumber = 2;
  inline bool start() const;
  inline void set_start(bool value);
  
  // @@protoc_insertion_point(class_scope:dns_analysis_results.ControlMessage)
 private:
  inline void set_has_timestamp();
  inline void clear_has_timestamp();
  inline void set_has_start();
  inline void clear_has_start();
  
  ::google::protobuf::UnknownFieldSet _unknown_fields_;
  
  ::google::protobuf::uint32 timestamp_;
  bool start_;
  
  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(2 + 31) / 32];
  
  friend void  protobuf_AddDesc_dns_5fanalysis_5fresults_2eproto();
  friend void protobuf_AssignDesc_dns_5fanalysis_5fresults_2eproto();
  friend void protobuf_ShutdownFile_dns_5fanalysis_5fresults_2eproto();
  
  void InitAsDefaultInstance();
  static dns_analysis_results_ControlMessage* default_instance_;
};
// -------------------------------------------------------------------

class dns_analysis_results : public ::google::protobuf::Message {
 public:
  dns_analysis_results();
  virtual ~dns_analysis_results();
  
  dns_analysis_results(const dns_analysis_results& from);
  
  inline dns_analysis_results& operator=(const dns_analysis_results& from) {
    CopyFrom(from);
    return *this;
  }
  
  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }
  
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }
  
  static const ::google::protobuf::Descriptor* descriptor();
  static const dns_analysis_results& default_instance();
  
  void Swap(dns_analysis_results* other);
  
  // implements Message ----------------------------------------------
  
  dns_analysis_results* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const dns_analysis_results& from);
  void MergeFrom(const dns_analysis_results& from);
  void Clear();
  bool IsInitialized() const;
  
  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:
  
  ::google::protobuf::Metadata GetMetadata() const;
  
  // nested types ----------------------------------------------------
  
  typedef dns_analysis_results_DataMessage DataMessage;
  typedef dns_analysis_results_ControlMessage ControlMessage;
  
  // accessors -------------------------------------------------------
  
  // optional .dns_analysis_results.DataMessage data = 1;
  inline bool has_data() const;
  inline void clear_data();
  static const int kDataFieldNumber = 1;
  inline const ::dns_analysis_results_DataMessage& data() const;
  inline ::dns_analysis_results_DataMessage* mutable_data();
  inline ::dns_analysis_results_DataMessage* release_data();
  
  // optional .dns_analysis_results.ControlMessage control = 2;
  inline bool has_control() const;
  inline void clear_control();
  static const int kControlFieldNumber = 2;
  inline const ::dns_analysis_results_ControlMessage& control() const;
  inline ::dns_analysis_results_ControlMessage* mutable_control();
  inline ::dns_analysis_results_ControlMessage* release_control();
  
  // @@protoc_insertion_point(class_scope:dns_analysis_results)
 private:
  inline void set_has_data();
  inline void clear_has_data();
  inline void set_has_control();
  inline void clear_has_control();
  
  ::google::protobuf::UnknownFieldSet _unknown_fields_;
  
  ::dns_analysis_results_DataMessage* data_;
  ::dns_analysis_results_ControlMessage* control_;
  
  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(2 + 31) / 32];
  
  friend void  protobuf_AddDesc_dns_5fanalysis_5fresults_2eproto();
  friend void protobuf_AssignDesc_dns_5fanalysis_5fresults_2eproto();
  friend void protobuf_ShutdownFile_dns_5fanalysis_5fresults_2eproto();
  
  void InitAsDefaultInstance();
  static dns_analysis_results* default_instance_;
};
// ===================================================================


// ===================================================================

// dns_analysis_results_DataMessage

// required string dname = 1;
inline bool dns_analysis_results_DataMessage::has_dname() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void dns_analysis_results_DataMessage::set_has_dname() {
  _has_bits_[0] |= 0x00000001u;
}
inline void dns_analysis_results_DataMessage::clear_has_dname() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void dns_analysis_results_DataMessage::clear_dname() {
  if (dname_ != &::google::protobuf::internal::kEmptyString) {
    dname_->clear();
  }
  clear_has_dname();
}
inline const ::std::string& dns_analysis_results_DataMessage::dname() const {
  return *dname_;
}
inline void dns_analysis_results_DataMessage::set_dname(const ::std::string& value) {
  set_has_dname();
  if (dname_ == &::google::protobuf::internal::kEmptyString) {
    dname_ = new ::std::string;
  }
  dname_->assign(value);
}
inline void dns_analysis_results_DataMessage::set_dname(const char* value) {
  set_has_dname();
  if (dname_ == &::google::protobuf::internal::kEmptyString) {
    dname_ = new ::std::string;
  }
  dname_->assign(value);
}
inline void dns_analysis_results_DataMessage::set_dname(const char* value, size_t size) {
  set_has_dname();
  if (dname_ == &::google::protobuf::internal::kEmptyString) {
    dname_ = new ::std::string;
  }
  dname_->assign(reinterpret_cast<const char*>(value), size);
}
inline ::std::string* dns_analysis_results_DataMessage::mutable_dname() {
  set_has_dname();
  if (dname_ == &::google::protobuf::internal::kEmptyString) {
    dname_ = new ::std::string;
  }
  return dname_;
}
inline ::std::string* dns_analysis_results_DataMessage::release_dname() {
  clear_has_dname();
  if (dname_ == &::google::protobuf::internal::kEmptyString) {
    return NULL;
  } else {
    ::std::string* temp = dname_;
    dname_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
    return temp;
  }
}

// required uint32 timestamp = 2;
inline bool dns_analysis_results_DataMessage::has_timestamp() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void dns_analysis_results_DataMessage::set_has_timestamp() {
  _has_bits_[0] |= 0x00000002u;
}
inline void dns_analysis_results_DataMessage::clear_has_timestamp() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void dns_analysis_results_DataMessage::clear_timestamp() {
  timestamp_ = 0u;
  clear_has_timestamp();
}
inline ::google::protobuf::uint32 dns_analysis_results_DataMessage::timestamp() const {
  return timestamp_;
}
inline void dns_analysis_results_DataMessage::set_timestamp(::google::protobuf::uint32 value) {
  set_has_timestamp();
  timestamp_ = value;
}

// required bool whitelisted = 3;
inline bool dns_analysis_results_DataMessage::has_whitelisted() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void dns_analysis_results_DataMessage::set_has_whitelisted() {
  _has_bits_[0] |= 0x00000004u;
}
inline void dns_analysis_results_DataMessage::clear_has_whitelisted() {
  _has_bits_[0] &= ~0x00000004u;
}
inline void dns_analysis_results_DataMessage::clear_whitelisted() {
  whitelisted_ = false;
  clear_has_whitelisted();
}
inline bool dns_analysis_results_DataMessage::whitelisted() const {
  return whitelisted_;
}
inline void dns_analysis_results_DataMessage::set_whitelisted(bool value) {
  set_has_whitelisted();
  whitelisted_ = value;
}

// required float score = 4;
inline bool dns_analysis_results_DataMessage::has_score() const {
  return (_has_bits_[0] & 0x00000008u) != 0;
}
inline void dns_analysis_results_DataMessage::set_has_score() {
  _has_bits_[0] |= 0x00000008u;
}
inline void dns_analysis_results_DataMessage::clear_has_score() {
  _has_bits_[0] &= ~0x00000008u;
}
inline void dns_analysis_results_DataMessage::clear_score() {
  score_ = 0;
  clear_has_score();
}
inline float dns_analysis_results_DataMessage::score() const {
  return score_;
}
inline void dns_analysis_results_DataMessage::set_score(float value) {
  set_has_score();
  score_ = value;
}

// -------------------------------------------------------------------

// dns_analysis_results_ControlMessage

// required uint32 timestamp = 1;
inline bool dns_analysis_results_ControlMessage::has_timestamp() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void dns_analysis_results_ControlMessage::set_has_timestamp() {
  _has_bits_[0] |= 0x00000001u;
}
inline void dns_analysis_results_ControlMessage::clear_has_timestamp() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void dns_analysis_results_ControlMessage::clear_timestamp() {
  timestamp_ = 0u;
  clear_has_timestamp();
}
inline ::google::protobuf::uint32 dns_analysis_results_ControlMessage::timestamp() const {
  return timestamp_;
}
inline void dns_analysis_results_ControlMessage::set_timestamp(::google::protobuf::uint32 value) {
  set_has_timestamp();
  timestamp_ = value;
}

// required bool start = 2;
inline bool dns_analysis_results_ControlMessage::has_start() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void dns_analysis_results_ControlMessage::set_has_start() {
  _has_bits_[0] |= 0x00000002u;
}
inline void dns_analysis_results_ControlMessage::clear_has_start() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void dns_analysis_results_ControlMessage::clear_start() {
  start_ = false;
  clear_has_start();
}
inline bool dns_analysis_results_ControlMessage::start() const {
  return start_;
}
inline void dns_analysis_results_ControlMessage::set_start(bool value) {
  set_has_start();
  start_ = value;
}

// -------------------------------------------------------------------

// dns_analysis_results

// optional .dns_analysis_results.DataMessage data = 1;
inline bool dns_analysis_results::has_data() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void dns_analysis_results::set_has_data() {
  _has_bits_[0] |= 0x00000001u;
}
inline void dns_analysis_results::clear_has_data() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void dns_analysis_results::clear_data() {
  if (data_ != NULL) data_->::dns_analysis_results_DataMessage::Clear();
  clear_has_data();
}
inline const ::dns_analysis_results_DataMessage& dns_analysis_results::data() const {
  return data_ != NULL ? *data_ : *default_instance_->data_;
}
inline ::dns_analysis_results_DataMessage* dns_analysis_results::mutable_data() {
  set_has_data();
  if (data_ == NULL) data_ = new ::dns_analysis_results_DataMessage;
  return data_;
}
inline ::dns_analysis_results_DataMessage* dns_analysis_results::release_data() {
  clear_has_data();
  ::dns_analysis_results_DataMessage* temp = data_;
  data_ = NULL;
  return temp;
}

// optional .dns_analysis_results.ControlMessage control = 2;
inline bool dns_analysis_results::has_control() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void dns_analysis_results::set_has_control() {
  _has_bits_[0] |= 0x00000002u;
}
inline void dns_analysis_results::clear_has_control() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void dns_analysis_results::clear_control() {
  if (control_ != NULL) control_->::dns_analysis_results_ControlMessage::Clear();
  clear_has_control();
}
inline const ::dns_analysis_results_ControlMessage& dns_analysis_results::control() const {
  return control_ != NULL ? *control_ : *default_instance_->control_;
}
inline ::dns_analysis_results_ControlMessage* dns_analysis_results::mutable_control() {
  set_has_control();
  if (control_ == NULL) control_ = new ::dns_analysis_results_ControlMessage;
  return control_;
}
inline ::dns_analysis_results_ControlMessage* dns_analysis_results::release_control() {
  clear_has_control();
  ::dns_analysis_results_ControlMessage* temp = control_;
  control_ = NULL;
  return temp;
}


// @@protoc_insertion_point(namespace_scope)

#ifndef SWIG
namespace google {
namespace protobuf {


}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_dns_5fanalysis_5fresults_2eproto__INCLUDED