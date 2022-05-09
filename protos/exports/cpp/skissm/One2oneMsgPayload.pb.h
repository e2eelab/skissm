// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/One2oneMsgPayload.proto

#ifndef GOOGLE_PROTOBUF_INCLUDED_skissm_2fOne2oneMsgPayload_2eproto
#define GOOGLE_PROTOBUF_INCLUDED_skissm_2fOne2oneMsgPayload_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3019000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3019004 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/metadata_lite.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_skissm_2fOne2oneMsgPayload_2eproto
PROTOBUF_NAMESPACE_OPEN
namespace internal {
class AnyMetadata;
}  // namespace internal
PROTOBUF_NAMESPACE_CLOSE

// Internal implementation detail -- do not use these members.
struct TableStruct_skissm_2fOne2oneMsgPayload_2eproto {
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTableField entries[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::AuxiliaryParseTableField aux[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::ParseTable schema[1]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::PROTOBUF_NAMESPACE_ID::internal::FieldMetadata field_metadata[];
  static const ::PROTOBUF_NAMESPACE_ID::internal::SerializationTable serialization_table[];
  static const uint32_t offsets[];
};
extern const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fOne2oneMsgPayload_2eproto;
namespace skissm {
class One2oneMsgPayload;
struct One2oneMsgPayloadDefaultTypeInternal;
extern One2oneMsgPayloadDefaultTypeInternal _One2oneMsgPayload_default_instance_;
}  // namespace skissm
PROTOBUF_NAMESPACE_OPEN
template<> ::skissm::One2oneMsgPayload* Arena::CreateMaybeMessage<::skissm::One2oneMsgPayload>(Arena*);
PROTOBUF_NAMESPACE_CLOSE
namespace skissm {

// ===================================================================

class One2oneMsgPayload final :
    public ::PROTOBUF_NAMESPACE_ID::Message /* @@protoc_insertion_point(class_definition:skissm.One2oneMsgPayload) */ {
 public:
  inline One2oneMsgPayload() : One2oneMsgPayload(nullptr) {}
  ~One2oneMsgPayload() override;
  explicit constexpr One2oneMsgPayload(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized);

  One2oneMsgPayload(const One2oneMsgPayload& from);
  One2oneMsgPayload(One2oneMsgPayload&& from) noexcept
    : One2oneMsgPayload() {
    *this = ::std::move(from);
  }

  inline One2oneMsgPayload& operator=(const One2oneMsgPayload& from) {
    CopyFrom(from);
    return *this;
  }
  inline One2oneMsgPayload& operator=(One2oneMsgPayload&& from) noexcept {
    if (this == &from) return *this;
    if (GetOwningArena() == from.GetOwningArena()
  #ifdef PROTOBUF_FORCE_COPY_IN_MOVE
        && GetOwningArena() != nullptr
  #endif  // !PROTOBUF_FORCE_COPY_IN_MOVE
    ) {
      InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }

  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* descriptor() {
    return GetDescriptor();
  }
  static const ::PROTOBUF_NAMESPACE_ID::Descriptor* GetDescriptor() {
    return default_instance().GetMetadata().descriptor;
  }
  static const ::PROTOBUF_NAMESPACE_ID::Reflection* GetReflection() {
    return default_instance().GetMetadata().reflection;
  }
  static const One2oneMsgPayload& default_instance() {
    return *internal_default_instance();
  }
  static inline const One2oneMsgPayload* internal_default_instance() {
    return reinterpret_cast<const One2oneMsgPayload*>(
               &_One2oneMsgPayload_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  friend void swap(One2oneMsgPayload& a, One2oneMsgPayload& b) {
    a.Swap(&b);
  }
  inline void Swap(One2oneMsgPayload* other) {
    if (other == this) return;
  #ifdef PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() != nullptr &&
        GetOwningArena() == other->GetOwningArena()) {
   #else  // PROTOBUF_FORCE_COPY_IN_SWAP
    if (GetOwningArena() == other->GetOwningArena()) {
  #endif  // !PROTOBUF_FORCE_COPY_IN_SWAP
      InternalSwap(other);
    } else {
      ::PROTOBUF_NAMESPACE_ID::internal::GenericSwap(this, other);
    }
  }
  void UnsafeArenaSwap(One2oneMsgPayload* other) {
    if (other == this) return;
    GOOGLE_DCHECK(GetOwningArena() == other->GetOwningArena());
    InternalSwap(other);
  }

  // implements Message ----------------------------------------------

  One2oneMsgPayload* New(::PROTOBUF_NAMESPACE_ID::Arena* arena = nullptr) const final {
    return CreateMaybeMessage<One2oneMsgPayload>(arena);
  }
  using ::PROTOBUF_NAMESPACE_ID::Message::CopyFrom;
  void CopyFrom(const One2oneMsgPayload& from);
  using ::PROTOBUF_NAMESPACE_ID::Message::MergeFrom;
  void MergeFrom(const One2oneMsgPayload& from);
  private:
  static void MergeImpl(::PROTOBUF_NAMESPACE_ID::Message* to, const ::PROTOBUF_NAMESPACE_ID::Message& from);
  public:
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  const char* _InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) final;
  uint8_t* _InternalSerialize(
      uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(One2oneMsgPayload* other);

  private:
  friend class ::PROTOBUF_NAMESPACE_ID::internal::AnyMetadata;
  static ::PROTOBUF_NAMESPACE_ID::StringPiece FullMessageName() {
    return "skissm.One2oneMsgPayload";
  }
  protected:
  explicit One2oneMsgPayload(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                       bool is_message_owned = false);
  private:
  static void ArenaDtor(void* object);
  inline void RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena* arena);
  public:

  static const ClassData _class_data_;
  const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*GetClassData() const final;

  ::PROTOBUF_NAMESPACE_ID::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  enum : int {
    kCiphertextFieldNumber = 2,
    kRatchetKeyFieldNumber = 3,
    kSequenceFieldNumber = 1,
  };
  // bytes ciphertext = 2;
  void clear_ciphertext();
  const std::string& ciphertext() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_ciphertext(ArgT0&& arg0, ArgT... args);
  std::string* mutable_ciphertext();
  PROTOBUF_NODISCARD std::string* release_ciphertext();
  void set_allocated_ciphertext(std::string* ciphertext);
  private:
  const std::string& _internal_ciphertext() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_ciphertext(const std::string& value);
  std::string* _internal_mutable_ciphertext();
  public:

  // bytes ratchet_key = 3;
  void clear_ratchet_key();
  const std::string& ratchet_key() const;
  template <typename ArgT0 = const std::string&, typename... ArgT>
  void set_ratchet_key(ArgT0&& arg0, ArgT... args);
  std::string* mutable_ratchet_key();
  PROTOBUF_NODISCARD std::string* release_ratchet_key();
  void set_allocated_ratchet_key(std::string* ratchet_key);
  private:
  const std::string& _internal_ratchet_key() const;
  inline PROTOBUF_ALWAYS_INLINE void _internal_set_ratchet_key(const std::string& value);
  std::string* _internal_mutable_ratchet_key();
  public:

  // uint32 sequence = 1;
  void clear_sequence();
  uint32_t sequence() const;
  void set_sequence(uint32_t value);
  private:
  uint32_t _internal_sequence() const;
  void _internal_set_sequence(uint32_t value);
  public:

  // @@protoc_insertion_point(class_scope:skissm.One2oneMsgPayload)
 private:
  class _Internal;

  template <typename T> friend class ::PROTOBUF_NAMESPACE_ID::Arena::InternalHelper;
  typedef void InternalArenaConstructable_;
  typedef void DestructorSkippable_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr ciphertext_;
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr ratchet_key_;
  uint32_t sequence_;
  mutable ::PROTOBUF_NAMESPACE_ID::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_skissm_2fOne2oneMsgPayload_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// One2oneMsgPayload

// uint32 sequence = 1;
inline void One2oneMsgPayload::clear_sequence() {
  sequence_ = 0u;
}
inline uint32_t One2oneMsgPayload::_internal_sequence() const {
  return sequence_;
}
inline uint32_t One2oneMsgPayload::sequence() const {
  // @@protoc_insertion_point(field_get:skissm.One2oneMsgPayload.sequence)
  return _internal_sequence();
}
inline void One2oneMsgPayload::_internal_set_sequence(uint32_t value) {
  
  sequence_ = value;
}
inline void One2oneMsgPayload::set_sequence(uint32_t value) {
  _internal_set_sequence(value);
  // @@protoc_insertion_point(field_set:skissm.One2oneMsgPayload.sequence)
}

// bytes ciphertext = 2;
inline void One2oneMsgPayload::clear_ciphertext() {
  ciphertext_.ClearToEmpty();
}
inline const std::string& One2oneMsgPayload::ciphertext() const {
  // @@protoc_insertion_point(field_get:skissm.One2oneMsgPayload.ciphertext)
  return _internal_ciphertext();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void One2oneMsgPayload::set_ciphertext(ArgT0&& arg0, ArgT... args) {
 
 ciphertext_.SetBytes(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:skissm.One2oneMsgPayload.ciphertext)
}
inline std::string* One2oneMsgPayload::mutable_ciphertext() {
  std::string* _s = _internal_mutable_ciphertext();
  // @@protoc_insertion_point(field_mutable:skissm.One2oneMsgPayload.ciphertext)
  return _s;
}
inline const std::string& One2oneMsgPayload::_internal_ciphertext() const {
  return ciphertext_.Get();
}
inline void One2oneMsgPayload::_internal_set_ciphertext(const std::string& value) {
  
  ciphertext_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* One2oneMsgPayload::_internal_mutable_ciphertext() {
  
  return ciphertext_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* One2oneMsgPayload::release_ciphertext() {
  // @@protoc_insertion_point(field_release:skissm.One2oneMsgPayload.ciphertext)
  return ciphertext_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void One2oneMsgPayload::set_allocated_ciphertext(std::string* ciphertext) {
  if (ciphertext != nullptr) {
    
  } else {
    
  }
  ciphertext_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ciphertext,
      GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (ciphertext_.IsDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited())) {
    ciphertext_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:skissm.One2oneMsgPayload.ciphertext)
}

// bytes ratchet_key = 3;
inline void One2oneMsgPayload::clear_ratchet_key() {
  ratchet_key_.ClearToEmpty();
}
inline const std::string& One2oneMsgPayload::ratchet_key() const {
  // @@protoc_insertion_point(field_get:skissm.One2oneMsgPayload.ratchet_key)
  return _internal_ratchet_key();
}
template <typename ArgT0, typename... ArgT>
inline PROTOBUF_ALWAYS_INLINE
void One2oneMsgPayload::set_ratchet_key(ArgT0&& arg0, ArgT... args) {
 
 ratchet_key_.SetBytes(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, static_cast<ArgT0 &&>(arg0), args..., GetArenaForAllocation());
  // @@protoc_insertion_point(field_set:skissm.One2oneMsgPayload.ratchet_key)
}
inline std::string* One2oneMsgPayload::mutable_ratchet_key() {
  std::string* _s = _internal_mutable_ratchet_key();
  // @@protoc_insertion_point(field_mutable:skissm.One2oneMsgPayload.ratchet_key)
  return _s;
}
inline const std::string& One2oneMsgPayload::_internal_ratchet_key() const {
  return ratchet_key_.Get();
}
inline void One2oneMsgPayload::_internal_set_ratchet_key(const std::string& value) {
  
  ratchet_key_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, value, GetArenaForAllocation());
}
inline std::string* One2oneMsgPayload::_internal_mutable_ratchet_key() {
  
  return ratchet_key_.Mutable(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, GetArenaForAllocation());
}
inline std::string* One2oneMsgPayload::release_ratchet_key() {
  // @@protoc_insertion_point(field_release:skissm.One2oneMsgPayload.ratchet_key)
  return ratchet_key_.Release(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), GetArenaForAllocation());
}
inline void One2oneMsgPayload::set_allocated_ratchet_key(std::string* ratchet_key) {
  if (ratchet_key != nullptr) {
    
  } else {
    
  }
  ratchet_key_.SetAllocated(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), ratchet_key,
      GetArenaForAllocation());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (ratchet_key_.IsDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited())) {
    ratchet_key_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
  }
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  // @@protoc_insertion_point(field_set_allocated:skissm.One2oneMsgPayload.ratchet_key)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__

// @@protoc_insertion_point(namespace_scope)

}  // namespace skissm

// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // GOOGLE_PROTOBUF_INCLUDED_GOOGLE_PROTOBUF_INCLUDED_skissm_2fOne2oneMsgPayload_2eproto